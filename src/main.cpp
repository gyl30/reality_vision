#include "config.hpp"
#include "protocol_tests.hpp"
#include "reality_config.hpp"
#include "reality_stream.hpp"
#include "socks5_protocol.hpp"
#include "sniffer.hpp"
#include "tcp_byte_stream.hpp"
#include "vision_stream.hpp"
#include "vless_header.hpp"
#include "vless_stream.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/errc.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <future>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace
{

using tcp = boost::asio::ip::tcp;

boost::asio::awaitable<void> relay_client_to_upstream(tcp::socket& client_socket, rv::vision::vision_stream& upstream, boost::system::error_code& ec)
{
    std::array<std::uint8_t, 16UL * 1024U> buffer{};
    for (;;)
    {
        const auto count =
            co_await client_socket.async_read_some(boost::asio::buffer(buffer), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::eof || (!ec && count == 0))
        {
            ec.clear();
            co_await upstream.shutdown_send(ec);
            if (ec)
            {
                upstream.shutdown();
            }
            co_return;
        }
        if (ec)
        {
            upstream.shutdown();
            co_return;
        }

        co_await upstream.write(std::span<const std::uint8_t>(buffer.data(), count), ec);
        if (ec)
        {
            upstream.shutdown();
            co_return;
        }
    }
}

boost::asio::awaitable<void> relay_upstream_to_client(rv::vision::vision_stream& upstream, tcp::socket& client_socket, boost::system::error_code& ec)
{
    std::array<std::uint8_t, 16UL * 1024U> buffer{};
    for (;;)
    {
        const auto count = co_await upstream.read(buffer, ec);
        if (!ec && count == 0)
        {
            boost::system::error_code ignored;
            client_socket.shutdown(tcp::socket::shutdown_send, ignored);
            co_return;
        }
        if (ec)
        {
            boost::system::error_code ignored;
            client_socket.close(ignored);
            co_return;
        }

        co_await boost::asio::async_write(
            client_socket, boost::asio::buffer(buffer.data(), count), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            upstream.shutdown();
            co_return;
        }
    }
}

boost::asio::awaitable<void> relay_bidirectional(tcp::socket& client_socket, rv::vision::vision_stream& upstream, boost::system::error_code& ec)
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    boost::system::error_code client_to_upstream_ec;
    boost::system::error_code upstream_to_client_ec;
    co_await (relay_client_to_upstream(client_socket, upstream, client_to_upstream_ec) &&
              relay_upstream_to_client(upstream, client_socket, upstream_to_client_ec));

    boost::system::error_code ignored;
    client_socket.shutdown(tcp::socket::shutdown_both, ignored);
    client_socket.close(ignored);
    upstream.shutdown();

    if (client_to_upstream_ec && client_to_upstream_ec != boost::asio::error::operation_aborted)
    {
        ec = client_to_upstream_ec;
    }
    else if (upstream_to_client_ec && upstream_to_client_ec != boost::asio::error::operation_aborted)
    {
        ec = upstream_to_client_ec;
    }
}

rv::vless::address to_vless_address(const rv::socks5::address& address)
{
    return std::visit(
        []<typename address_type>(const address_type& value) -> rv::vless::address
        {
            if constexpr (std::is_same_v<address_type, rv::socks5::ipv4_address>)
            {
                return rv::vless::ipv4_address{value.bytes};
            }
            else if constexpr (std::is_same_v<address_type, rv::socks5::ipv6_address>)
            {
                return rv::vless::ipv6_address{value.bytes};
            }
            else
            {
                return rv::vless::domain_address{value.name};
            }
        },
        address);
}

boost::asio::awaitable<std::optional<rv::reality::reality_stream>> connect_reality(const rv::app::config& configuration,
                                                                                   const std::string& session_id,
                                                                                   boost::system::error_code& ec)
{
    const auto executor = co_await boost::asio::this_coro::executor;
    auto tcp_stream = co_await rv::net::tcp_byte_stream::connect(
        executor, configuration.reality_server_host, std::to_string(configuration.reality_server_port), session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    rv::reality::client_config reality_configuration;
    reality_configuration.server_name = configuration.reality_server_name;
    reality_configuration.server_public_key = configuration.reality_server_public_key;
    reality_configuration.short_id = configuration.reality_short_id;
    co_return co_await rv::reality::reality_stream::connect(std::move(*tcp_stream), std::move(reality_configuration), session_id, ec);
}

boost::asio::awaitable<std::optional<rv::vision::vision_stream>> connect_vision(rv::reality::reality_stream reality,
                                                                                const rv::app::config& configuration,
                                                                                const rv::socks5::connect_request& request,
                                                                                const std::string& session_id,
                                                                                boost::system::error_code& ec)
{
    rv::vless::client_config vless_configuration;
    vless_configuration.user_id = configuration.vless_user_id;
    vless_configuration.destination = to_vless_address(request.destination);
    vless_configuration.destination_port = request.port;
    auto vless_stream = co_await rv::vless::vless_stream::connect(std::move(reality), std::move(vless_configuration), session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_return co_await rv::vision::vision_stream::connect(std::move(*vless_stream), configuration.vless_user_id, session_id, ec);
}

struct initial_client_data
{
    std::vector<std::uint8_t> bytes;
    std::optional<std::string> domain;
};

boost::asio::awaitable<std::optional<std::size_t>> read_some_until(tcp::socket& client_socket,
                                                                   std::span<std::uint8_t> output,
                                                                   const std::chrono::steady_clock::time_point deadline,
                                                                   boost::system::error_code& ec)
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    boost::asio::steady_timer timer(client_socket.get_executor());
    timer.expires_at(deadline);
    boost::system::error_code timer_ec;
    const auto outcome =
        co_await (client_socket.async_read_some(boost::asio::buffer(output), boost::asio::redirect_error(boost::asio::use_awaitable, ec)) ||
                  timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, timer_ec)));

    if (outcome.index() == 1)
    {
        ec.clear();
        co_return std::nullopt;
    }
    co_return std::get<0>(outcome);
}

boost::asio::awaitable<initial_client_data> sniff_initial_client_data(tcp::socket& client_socket, boost::system::error_code& ec)
{
    constexpr std::size_t sniff_limit = 16UL * 1024U;
    constexpr auto sniff_timeout = std::chrono::milliseconds(200);

    initial_client_data output;
    output.bytes.reserve(sniff_limit);
    std::array<std::uint8_t, 4096> buffer{};
    const auto deadline = std::chrono::steady_clock::now() + sniff_timeout;

    for (;;)
    {
        const auto sniff_result = rv::sniff::inspect_destination(output.bytes);
        if (sniff_result.state == rv::sniff::status::found)
        {
            output.domain = sniff_result.domain;
            co_return output;
        }
        if (sniff_result.state == rv::sniff::status::no_match || output.bytes.size() == sniff_limit)
        {
            co_return output;
        }

        const auto requested = std::min(buffer.size(), sniff_limit - output.bytes.size());
        const auto count = co_await read_some_until(client_socket, std::span(buffer.data(), requested), deadline, ec);
        if (ec || !count)
        {
            co_return output;
        }
        if (*count == 0)
        {
            ec = boost::asio::error::eof;
            co_return output;
        }
        output.bytes.insert(output.bytes.end(), buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*count));
    }
}

[[nodiscard]] bool should_sniff_destination(const rv::socks5::connect_request& request) noexcept
{
    return !std::holds_alternative<rv::socks5::domain_address>(request.destination);
}

rv::socks5::reply map_error_to_socks_reply(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::connection_refused)
    {
        return rv::socks5::reply::connection_refused;
    }
    if (ec == boost::asio::error::network_unreachable)
    {
        return rv::socks5::reply::network_unreachable;
    }
    if (ec == boost::asio::error::host_unreachable || ec == boost::asio::error::host_not_found || ec == boost::asio::error::host_not_found_try_again)
    {
        return rv::socks5::reply::host_unreachable;
    }
    return rv::socks5::reply::general_failure;
}

boost::asio::awaitable<void> send_upstream_failure_reply(tcp::socket& client_socket, const boost::system::error_code& upstream_ec)
{
    boost::system::error_code ignored;
    co_await rv::socks5::send_reply(client_socket, map_error_to_socks_reply(upstream_ec), ignored);
}

boost::asio::awaitable<void> run_socks_session(tcp::socket client_socket, rv::app::config configuration, std::string session_id)
{
    boost::system::error_code ec;
    const auto request = co_await rv::socks5::negotiate_connect(client_socket, configuration.socks_credentials, ec);
    if (ec)
    {
        spdlog::warn("{} socks5 negotiation failed: {}", session_id, ec.message());
        co_return;
    }

    spdlog::info("{} socks5 connect {}", session_id, rv::socks5::format_destination(*request));
    auto reality = co_await connect_reality(configuration, session_id, ec);
    if (ec)
    {
        const auto upstream_ec = ec;
        co_await send_upstream_failure_reply(client_socket, upstream_ec);
        spdlog::warn("{} upstream connection failed: {}", session_id, upstream_ec.message());
        co_return;
    }

    auto effective_request = *request;
    initial_client_data initial_data;
    std::optional<rv::vision::vision_stream> upstream;

    if (should_sniff_destination(*request))
    {
        co_await rv::socks5::send_reply(client_socket, rv::socks5::reply::succeeded, ec);
        if (ec)
        {
            co_return;
        }

        initial_data = co_await sniff_initial_client_data(client_socket, ec);
        if (ec == boost::asio::error::eof)
        {
            ec.clear();
            co_return;
        }
        if (ec)
        {
            spdlog::warn("{} socks5 destination sniff failed: {}", session_id, ec.message());
            co_return;
        }

        if (initial_data.domain)
        {
            effective_request.destination = rv::socks5::domain_address{*initial_data.domain};
            spdlog::info("{} sniffed destination {}:{}", session_id, *initial_data.domain, effective_request.port);
        }

        upstream = co_await connect_vision(std::move(*reality), configuration, effective_request, session_id, ec);
        if (ec)
        {
            spdlog::warn("{} upstream connection failed after socks5 success: {}", session_id, ec.message());
            co_return;
        }
    }
    else
    {
        upstream = co_await connect_vision(std::move(*reality), configuration, effective_request, session_id, ec);
        if (ec)
        {
            const auto upstream_ec = ec;
            co_await send_upstream_failure_reply(client_socket, upstream_ec);
            spdlog::warn("{} upstream connection failed: {}", session_id, upstream_ec.message());
            co_return;
        }

        co_await rv::socks5::send_reply(client_socket, rv::socks5::reply::succeeded, ec);
        if (ec)
        {
            co_return;
        }
    }

    if (!initial_data.bytes.empty())
    {
        co_await upstream->write(initial_data.bytes, ec);
        if (ec)
        {
            spdlog::warn("{} socks5 relay failed: {}", session_id, ec.message());
            co_return;
        }
    }

    co_await relay_bidirectional(client_socket, *upstream, ec);
    if (ec)
    {
        spdlog::warn("{} socks5 relay failed: {}", session_id, ec.message());
        co_return;
    }

    spdlog::info("{} socks5 tcp session completed", session_id);
}

void log_session_exception(const std::string& session_id, const std::exception_ptr& exception)
{
    if (!exception)
    {
        return;
    }

    try
    {
        std::rethrow_exception(exception);
    }
    catch (const std::exception& error)
    {
        spdlog::error("{} unexpected session exception: {}", session_id, error.what());
    }
    catch (...)
    {
        spdlog::error("{} unexpected non-standard session exception", session_id);
    }
}

tcp::acceptor create_socks_acceptor(boost::asio::any_io_executor executor, const std::uint16_t port, boost::system::error_code& ec)
{
    tcp::acceptor acceptor(executor);
    acceptor.open(tcp::v4(), ec);
    if (ec)
    {
        return acceptor;
    }

    acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return acceptor;
    }

    acceptor.bind(tcp::endpoint(boost::asio::ip::address_v4::loopback(), port), ec);
    if (ec)
    {
        return acceptor;
    }

    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        return acceptor;
    }

    return acceptor;
}

boost::asio::awaitable<void> run_socks_server(rv::app::config configuration, boost::system::error_code& ec)
{
    const auto executor = co_await boost::asio::this_coro::executor;
    auto acceptor = create_socks_acceptor(executor, configuration.socks_listen_port, ec);
    if (ec)
    {
        co_return;
    }

    spdlog::info("socks5 tcp proxy listening on 127.0.0.1:{}", configuration.socks_listen_port);
    std::uint64_t next_session_number = 1;
    for (;;)
    {
        auto client_socket = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }

        std::string session_id{"socks_" + std::to_string(next_session_number++)};
        boost::asio::co_spawn(executor,
                              run_socks_session(std::move(client_socket), configuration, session_id),
                              [session_id](const std::exception_ptr& exception) { log_session_exception(session_id, exception); });
    }
}

}    // namespace

int main(int argc, char* argv[])
{
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S.%e %^%l%$ %v");

    try
    {
        const auto configuration = rv::app::parse_config(argc, argv);
        if (!configuration)
        {
            return 0;
        }
        if (configuration->self_test)
        {
            return rv::testing::run_protocol_tests();
        }

        boost::asio::io_context context(1);
        boost::system::error_code ec;
        auto server = boost::asio::co_spawn(context, run_socks_server(*configuration, ec), boost::asio::use_future);
        context.run();
        server.get();

        if (ec)
        {
            spdlog::error("reality vision failed: {}", ec.message());
            return 1;
        }
        return 0;
    }
    catch (const std::exception& error)
    {
        spdlog::error("unexpected fatal exception: {}", error.what());
        return 1;
    }
}

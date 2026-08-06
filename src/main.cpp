#include "config.hpp"
#include "protocol_tests.hpp"
#include "reality_config.hpp"
#include "reality_stream.hpp"
#include "socks5_protocol.hpp"
#include "tcp_byte_stream.hpp"
#include "vision_stream.hpp"
#include "vless_header.hpp"
#include "vless_stream.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <future>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>

namespace
{

template <typename stream_type>
boost::asio::awaitable<void> copy_local_to_remote(boost::asio::ip::tcp::socket& local, stream_type& remote, boost::system::error_code& ec)
{
    ec.clear();
    std::array<std::uint8_t, 16U * 1024U> buffer{};
    for (;;)
    {
        const auto count = co_await local.async_read_some(boost::asio::buffer(buffer), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::eof || (!ec && count == 0))
        {
            ec.clear();
            co_await remote.async_shutdown_send(ec);
            if (ec)
            {
                remote.shutdown();
            }
            co_return;
        }
        if (ec)
        {
            remote.shutdown();
            co_return;
        }

        co_await remote.async_write_all(std::span<const std::uint8_t>(buffer.data(), count), ec);
        if (ec)
        {
            remote.shutdown();
            co_return;
        }
    }
}

template <typename stream_type>
boost::asio::awaitable<void> copy_remote_to_local(stream_type& remote, boost::asio::ip::tcp::socket& local, boost::system::error_code& ec)
{
    ec.clear();
    std::array<std::uint8_t, 16U * 1024U> buffer{};
    for (;;)
    {
        const auto count = co_await remote.async_read_some(buffer, ec);
        if (!ec && count == 0)
        {
            boost::system::error_code ignored;
            local.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ignored);
            co_return;
        }
        if (ec)
        {
            boost::system::error_code ignored;
            local.close(ignored);
            co_return;
        }

        co_await boost::asio::async_write(
            local, boost::asio::buffer(buffer.data(), count), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            remote.shutdown();
            co_return;
        }
    }
}

template <typename stream_type>
boost::asio::awaitable<void> relay_bidirectional(boost::asio::ip::tcp::socket& local, stream_type& remote, boost::system::error_code& ec)
{
    using namespace boost::asio::experimental::awaitable_operators;

    boost::system::error_code uplink_ec;
    boost::system::error_code downlink_ec;
    co_await (copy_local_to_remote(local, remote, uplink_ec) && copy_remote_to_local(remote, local, downlink_ec));

    boost::system::error_code ignored;
    local.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
    local.close(ignored);
    remote.shutdown();

    ec.clear();
    if (uplink_ec && uplink_ec != boost::asio::error::operation_aborted)
    {
        ec = uplink_ec;
    }
    else if (downlink_ec && downlink_ec != boost::asio::error::operation_aborted)
    {
        ec = downlink_ec;
    }
}

rv::vless::address to_vless_address(const rv::socks5::address& address)
{
    return std::visit(
        []<typename type>(const type& value) -> rv::vless::address
        {
            using address_type = std::decay_t<type>;
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

boost::asio::awaitable<std::optional<rv::vless::vless_stream>> connect_vless(const rv::app::config& settings,
                                                                             rv::vless::address destination,
                                                                             std::uint16_t destination_port,
                                                                             const std::string& log,
                                                                             boost::system::error_code& ec)
{
    ec.clear();
    const auto executor = co_await boost::asio::this_coro::executor;
    auto tcp = co_await rv::net::tcp_byte_stream::connect(executor, settings.server, std::to_string(settings.port), log, ec);
    if (ec || !tcp)
    {
        co_return std::nullopt;
    }

    rv::reality::client_config reality_config;
    reality_config.server_name = settings.server_name;
    reality_config.server_public_key = settings.server_public_key;
    reality_config.short_id = settings.short_id;
    auto reality = co_await rv::reality::reality_stream::connect(std::move(*tcp), reality_config, log, ec);
    if (ec || !reality)
    {
        co_return std::nullopt;
    }

    rv::vless::client_config vless_config;
    vless_config.user_id = settings.user_id;
    vless_config.destination = std::move(destination);
    vless_config.destination_port = destination_port;
    vless_config.selected_flow = settings.vision ? rv::vless::flow::xtls_rprx_vision : rv::vless::flow::none;
    co_return co_await rv::vless::vless_stream::connect(std::move(*reality), std::move(vless_config), log, ec);
}

rv::socks5::reply reply_for_error(const boost::system::error_code& ec)
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

boost::asio::awaitable<void> run_socks_connection(boost::asio::ip::tcp::socket local, rv::app::config settings, std::string log)
{
    boost::system::error_code ec;
    const auto request = co_await rv::socks5::async_negotiate_connect(local, settings.socks_credentials, ec);
    if (ec || !request)
    {
        if (ec)
        {
            spdlog::warn("[{}] socks5 negotiation failed: {}", log, ec.message());
        }
        co_return;
    }
    spdlog::info("[{}] socks5 connect {}", log, rv::socks5::format_destination(*request));

    auto vless = co_await connect_vless(settings, to_vless_address(request->destination), request->port, log, ec);
    if (ec || !vless)
    {
        const auto connect_ec = ec;
        boost::system::error_code reply_ec;
        co_await rv::socks5::async_send_reply(local, reply_for_error(connect_ec), reply_ec);
        spdlog::warn("[{}] upstream connection failed: {}", log, connect_ec.message());
        co_return;
    }

    if (settings.vision)
    {
        auto vision = co_await rv::vision::vision_stream::connect(std::move(*vless), settings.user_id, log, ec);
        if (ec || !vision)
        {
            const auto connect_ec = ec;
            boost::system::error_code reply_ec;
            co_await rv::socks5::async_send_reply(local, rv::socks5::reply::general_failure, reply_ec);
            spdlog::warn("[{}] Vision setup failed: {}", log, connect_ec.message());
            co_return;
        }

        co_await rv::socks5::async_send_reply(local, rv::socks5::reply::succeeded, ec);
        if (ec)
        {
            co_return;
        }
        co_await relay_bidirectional(local, *vision, ec);
    }
    else
    {
        co_await rv::socks5::async_send_reply(local, rv::socks5::reply::succeeded, ec);
        if (ec)
        {
            co_return;
        }
        co_await relay_bidirectional(local, *vless, ec);
    }

    if (ec)
    {
        spdlog::warn("[{}] socks5 relay failed: {}", log, ec.message());
        co_return;
    }
    spdlog::info("[{}] socks5 tcp session completed", log);
}

boost::asio::awaitable<void> run_socks_server(rv::app::config settings, boost::system::error_code& ec)
{
    ec.clear();
    const auto executor = co_await boost::asio::this_coro::executor;
    boost::asio::ip::tcp::acceptor acceptor(executor);
    acceptor.open(boost::asio::ip::tcp::v4(), ec);
    if (ec)
    {
        co_return;
    }
    acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        co_return;
    }
    acceptor.bind(boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4::loopback(), settings.socks_port), ec);
    if (ec)
    {
        co_return;
    }
    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec)
    {
        co_return;
    }

    spdlog::info("socks5 tcp proxy listening on 127.0.0.1:{}", settings.socks_port);
    std::uint64_t next_connection_id = 1;
    for (;;)
    {
        auto local = co_await acceptor.async_accept(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }

        std::string id{"socks_" + std::to_string(next_connection_id++)};
        boost::asio::co_spawn(executor,
                              run_socks_connection(std::move(local), settings, id),
                              [id](std::exception_ptr exception)
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
                                      spdlog::error("[{}] unexpected session exception: {}", id, error.what());
                                  }
                                  catch (...)
                                  {
                                      spdlog::error("[{}] unexpected non-standard session exception", id);
                                  }
                              });
    }
}

}    // namespace

int main(int argc, char* argv[])
{
    try
    {
        const auto parsed = rv::app::parse_config(argc, argv);
        if (!parsed)
        {
            return 0;
        }
        const auto settings = *parsed;
        if (settings.self_test)
        {
            return rv::testing::run_protocol_tests();
        }

        boost::asio::io_context context(1);
        boost::system::error_code ec;
        auto result = boost::asio::co_spawn(context, run_socks_server(settings, ec), boost::asio::use_future);
        context.run();
        result.get();
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

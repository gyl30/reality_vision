#include "tcp_proxy.hpp"

#include "network_address.hpp"
#include "proxy_common.hpp"

#include "reality_stream.hpp"
#include "socks5_protocol.hpp"
#include "sniffer.hpp"
#include "transparent.hpp"
#include "udp_proxy.hpp"
#include "vision_stream.hpp"
#include "vless_header.hpp"
#include "vless_stream.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/error_code.hpp>
#include <boost/system/errc.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

namespace rv::tcp_proxy
{
namespace
{

using tcp = boost::asio::ip::tcp;

constexpr std::size_t kRelayBufferSize = 16UL * 1024U;
constexpr auto kSocksHandshakeTimeout = std::chrono::seconds(60);

enum class transparent_mode : std::uint8_t
{
    kRedirect,
    kTproxy,
};

struct initial_client_data
{
    std::vector<std::uint8_t> bytes;
    std::optional<std::string> domain;
};

boost::asio::awaitable<void> relay_client_to_upstream(tcp::socket& client_socket, rv::vision::vision_stream& upstream, boost::system::error_code& ec)
{
    std::array<std::uint8_t, kRelayBufferSize> buffer{};
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
    std::array<std::uint8_t, kRelayBufferSize> buffer{};
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

boost::asio::awaitable<void> relay_with_initial_data(tcp::socket& client_socket,
                                                     rv::vision::vision_stream& upstream,
                                                     const std::span<const std::uint8_t> initial_data,
                                                     boost::system::error_code& ec)
{
    if (!initial_data.empty())
    {
        co_await upstream.write(initial_data, ec);
        if (ec)
        {
            co_return;
        }
    }

    co_await relay_bidirectional(client_socket, upstream, ec);
}

rv::proxy::target make_proxy_target(const rv::socks5::request& request)
{
    return rv::proxy::target{
        .destination = request.destination,
        .port = request.port,
    };
}

rv::proxy::target make_proxy_target(const tcp::endpoint& endpoint)
{
    return rv::proxy::target{
        .destination = rv::net::ipv4_address{endpoint.address().to_v4().to_bytes()},
        .port = endpoint.port(),
    };
}

std::string format_endpoint(const tcp::endpoint& endpoint) { return endpoint.address().to_string() + ":" + std::to_string(endpoint.port()); }

boost::asio::awaitable<std::optional<rv::vision::vision_stream>> connect_vision(rv::reality::reality_stream reality,
                                                                                const rv::app::config& configuration,
                                                                                const rv::proxy::target& target,
                                                                                const std::string& session_id,
                                                                                boost::system::error_code& ec)
{
    rv::vless::client_config vless_configuration;
    vless_configuration.user_id = configuration.vless_user_id;
    vless_configuration.destination = target.destination;
    vless_configuration.destination_port = target.port;
    auto vless_stream = co_await rv::vless::vless_stream::connect(std::move(reality), std::move(vless_configuration), session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_return co_await rv::vision::vision_stream::connect(std::move(*vless_stream), configuration.vless_user_id, session_id, ec);
}

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
    constexpr std::size_t kSniffLimit = 16UL * 1024U;
    constexpr auto kSniffTimeout = std::chrono::milliseconds(200);

    initial_client_data output;
    output.bytes.reserve(kSniffLimit);
    std::array<std::uint8_t, 4096> buffer{};
    const auto deadline = std::chrono::steady_clock::now() + kSniffTimeout;

    for (;;)
    {
        const auto sniff_result = rv::sniff::inspect_destination(output.bytes);
        if (sniff_result.state == rv::sniff::status::kFound)
        {
            output.domain = sniff_result.domain;
            co_return output;
        }
        if (sniff_result.state == rv::sniff::status::kNoMatch || output.bytes.size() == kSniffLimit)
        {
            co_return output;
        }

        const auto requested = std::min(buffer.size(), kSniffLimit - output.bytes.size());
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

[[nodiscard]] bool should_sniff_destination(const rv::socks5::request& request) noexcept
{
    return !std::holds_alternative<rv::net::domain_address>(request.destination);
}

void apply_sniffed_destination(rv::proxy::target& target, const initial_client_data& initial_data, const std::string& session_id)
{
    if (!initial_data.domain)
    {
        return;
    }

    target.destination = rv::net::domain_address{*initial_data.domain};
    spdlog::info("{} sniffed destination {}:{}", session_id, *initial_data.domain, target.port);
}

boost::asio::awaitable<void> send_upstream_failure_reply(tcp::socket& client_socket, const boost::system::error_code& upstream_ec)
{
    auto response = rv::socks5::reply::kGeneralFailure;
    if (upstream_ec == boost::asio::error::connection_refused)
    {
        response = rv::socks5::reply::kConnectionRefused;
    }
    else if (upstream_ec == boost::asio::error::network_unreachable)
    {
        response = rv::socks5::reply::kNetworkUnreachable;
    }
    else if (upstream_ec == boost::asio::error::host_unreachable || upstream_ec == boost::asio::error::host_not_found ||
             upstream_ec == boost::asio::error::host_not_found_try_again)
    {
        response = rv::socks5::reply::kHostUnreachable;
    }

    boost::system::error_code ignored;
    co_await rv::socks5::send_reply(client_socket, response, ignored);
}

boost::asio::awaitable<void> run_socks_connect_session(tcp::socket& client_socket,
                                                       const rv::app::config& configuration,
                                                       const rv::socks5::request& request,
                                                       const std::string& session_id)
{
    boost::system::error_code ec;
    spdlog::info("{} socks5 connect {}", session_id, rv::net::format_address_port(request.destination, request.port));

    auto reality = co_await rv::proxy::connect_reality(configuration, session_id, ec);
    if (ec)
    {
        const auto upstream_ec = ec;
        co_await send_upstream_failure_reply(client_socket, upstream_ec);
        spdlog::warn("{} upstream connection failed: {}", session_id, upstream_ec.message());
        co_return;
    }

    auto target = make_proxy_target(request);
    initial_client_data initial_data;
    std::optional<rv::vision::vision_stream> upstream;

    if (should_sniff_destination(request))
    {
        co_await rv::socks5::send_reply(client_socket, rv::socks5::reply::kSucceeded, ec);
        if (ec)
        {
            co_return;
        }

        initial_data = co_await sniff_initial_client_data(client_socket, ec);
        if (ec == boost::asio::error::eof)
        {
            co_return;
        }
        if (ec)
        {
            spdlog::warn("{} socks5 destination sniff failed: {}", session_id, ec.message());
            co_return;
        }

        apply_sniffed_destination(target, initial_data, session_id);
        upstream = co_await connect_vision(std::move(*reality), configuration, target, session_id, ec);
        if (ec)
        {
            spdlog::warn("{} upstream connection failed after socks5 success: {}", session_id, ec.message());
            co_return;
        }
    }
    else
    {
        upstream = co_await connect_vision(std::move(*reality), configuration, target, session_id, ec);
        if (ec)
        {
            const auto upstream_ec = ec;
            co_await send_upstream_failure_reply(client_socket, upstream_ec);
            spdlog::warn("{} upstream connection failed: {}", session_id, upstream_ec.message());
            co_return;
        }

        co_await rv::socks5::send_reply(client_socket, rv::socks5::reply::kSucceeded, ec);
        if (ec)
        {
            co_return;
        }
    }

    co_await relay_with_initial_data(client_socket, *upstream, initial_data.bytes, ec);
    if (ec)
    {
        spdlog::warn("{} socks5 relay failed: {}", session_id, ec.message());
        co_return;
    }

    spdlog::info("{} socks5 tcp session completed", session_id);
}

boost::asio::awaitable<void> run_socks_session(tcp::socket& client_socket, rv::app::config configuration, std::string session_id)
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    boost::system::error_code ec;
    boost::asio::steady_timer timer(client_socket.get_executor());
    timer.expires_after(kSocksHandshakeTimeout);
    boost::system::error_code timer_ec;
    auto outcome = co_await (rv::socks5::negotiate(client_socket, configuration.socks_credentials, ec) ||
                             timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, timer_ec)));
    if (outcome.index() == 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::timed_out);
        spdlog::warn("{} socks5 negotiation failed: {}", session_id, ec.message());
        co_return;
    }

    auto request = std::get<0>(std::move(outcome));
    if (ec)
    {
        spdlog::warn("{} socks5 negotiation failed: {}", session_id, ec.message());
        co_return;
    }

    if (request->requested_command == rv::socks5::command::kUdpAssociate)
    {
        spdlog::info("{} socks5 udp associate {}", session_id, rv::net::format_address_port(request->destination, request->port));
        co_await rv::udp_proxy::run_socks_association(client_socket, std::move(configuration), *request, std::move(session_id));
        co_return;
    }

    co_await run_socks_connect_session(client_socket, configuration, *request, session_id);
}

void get_transparent_destination(tcp::socket& client_socket, const transparent_mode mode, tcp::endpoint& destination, boost::system::error_code& ec)
{
    if (mode == transparent_mode::kRedirect)
    {
        ec = rv::transparent::get_redirect_original_destination(client_socket, destination);
        return;
    }

    destination = client_socket.local_endpoint(ec);
}

boost::asio::awaitable<void> run_transparent_session(tcp::socket& client_socket,
                                                     rv::app::config configuration,
                                                     std::string session_id,
                                                     const transparent_mode mode)
{
    boost::system::error_code ec;
    tcp::endpoint original_destination;
    get_transparent_destination(client_socket, mode, original_destination, ec);
    if (ec)
    {
        spdlog::warn("{} original destination lookup failed: {}", session_id, ec.message());
        co_return;
    }

    spdlog::info("{} transparent connect {}", session_id, format_endpoint(original_destination));
    auto reality = co_await rv::proxy::connect_reality(configuration, session_id, ec);
    if (ec)
    {
        spdlog::warn("{} upstream connection failed: {}", session_id, ec.message());
        co_return;
    }

    auto initial_data = co_await sniff_initial_client_data(client_socket, ec);
    if (ec == boost::asio::error::eof)
    {
        co_return;
    }
    if (ec)
    {
        spdlog::warn("{} destination sniff failed: {}", session_id, ec.message());
        co_return;
    }

    auto target = make_proxy_target(original_destination);
    apply_sniffed_destination(target, initial_data, session_id);
    auto upstream = co_await connect_vision(std::move(*reality), configuration, target, session_id, ec);
    if (ec)
    {
        spdlog::warn("{} upstream connection failed: {}", session_id, ec.message());
        co_return;
    }

    co_await relay_with_initial_data(client_socket, *upstream, initial_data.bytes, ec);
    if (ec)
    {
        spdlog::warn("{} transparent relay failed: {}", session_id, ec.message());
        co_return;
    }

    spdlog::info("{} transparent tcp session completed", session_id);
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

void log_service_exception(const std::string& service_id, const std::exception_ptr& exception)
{
    if (!exception)
    {
        spdlog::error("{} stopped", service_id);
        return;
    }

    try
    {
        std::rethrow_exception(exception);
    }
    catch (const std::exception& error)
    {
        spdlog::error("{} stopped with exception: {}", service_id, error.what());
    }
    catch (...)
    {
        spdlog::error("{} stopped with non-standard exception", service_id);
    }
}

}    // namespace

socks_session::socks_session(tcp::socket socket, rv::app::config configuration, std::string session_id)
    : socket_(std::move(socket)), configuration_(std::move(configuration)), session_id_(std::move(session_id))
{
}

void socks_session::startup()
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(socket_.get_executor(),
                          run(),
                          [self](const std::exception_ptr& exception)
                          {
                              log_session_exception(self->session_id_, exception);
                              self->shutdown();
                          });
}

void socks_session::shutdown()
{
    const auto self = shared_from_this();
    boost::asio::post(socket_.get_executor(),
                      [self]
                      {
                          boost::system::error_code ignored;
                          self->socket_.close(ignored);
                      });
}

boost::asio::awaitable<void> socks_session::run() { co_await run_socks_session(socket_, configuration_, session_id_); }

redirect_session::redirect_session(tcp::socket socket, rv::app::config configuration, std::string session_id)
    : socket_(std::move(socket)), configuration_(std::move(configuration)), session_id_(std::move(session_id))
{
}

void redirect_session::startup()
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(socket_.get_executor(),
                          run(),
                          [self](const std::exception_ptr& exception)
                          {
                              log_session_exception(self->session_id_, exception);
                              self->shutdown();
                          });
}

void redirect_session::shutdown()
{
    const auto self = shared_from_this();
    boost::asio::post(socket_.get_executor(),
                      [self]
                      {
                          boost::system::error_code ignored;
                          self->socket_.close(ignored);
                      });
}

boost::asio::awaitable<void> redirect_session::run()
{
    co_await run_transparent_session(socket_, configuration_, session_id_, transparent_mode::kRedirect);
}

tcp_tproxy_session::tcp_tproxy_session(tcp::socket socket, rv::app::config configuration, std::string session_id)
    : socket_(std::move(socket)), configuration_(std::move(configuration)), session_id_(std::move(session_id))
{
}

void tcp_tproxy_session::startup()
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(socket_.get_executor(),
                          run(),
                          [self](const std::exception_ptr& exception)
                          {
                              log_session_exception(self->session_id_, exception);
                              self->shutdown();
                          });
}

void tcp_tproxy_session::shutdown()
{
    const auto self = shared_from_this();
    boost::asio::post(socket_.get_executor(),
                      [self]
                      {
                          boost::system::error_code ignored;
                          self->socket_.close(ignored);
                      });
}

boost::asio::awaitable<void> tcp_tproxy_session::run()
{
    co_await run_transparent_session(socket_, configuration_, session_id_, transparent_mode::kTproxy);
}

socks_service::socks_service(tcp::acceptor acceptor, rv::app::config configuration, std::string service_id)
    : acceptor_(std::move(acceptor)), configuration_(std::move(configuration)), service_id_(std::move(service_id))
{
}

void socks_service::startup()
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(acceptor_.get_executor(),
                          accept_connections(),
                          [self](const std::exception_ptr& exception)
                          {
                              log_service_exception(self->service_id_, exception);
                              self->shutdown();
                              static_cast<boost::asio::io_context&>(self->acceptor_.get_executor().context()).stop();
                          });
}

void socks_service::shutdown()
{
    const auto self = shared_from_this();
    boost::asio::post(acceptor_.get_executor(),
                      [self]
                      {
                          if (self->stopping_)
                          {
                              return;
                          }
                          self->stopping_ = true;
                          boost::system::error_code ignored;
                          self->acceptor_.close(ignored);
                      });
}

boost::asio::awaitable<void> socks_service::accept_connections()
{
    spdlog::info("socks5 tcp proxy listening on 127.0.0.1:{} ({})", acceptor_.local_endpoint().port(), service_id_);
    for (;;)
    {
        auto socket = co_await acceptor_.async_accept(boost::asio::use_awaitable);
        auto session_id = service_id_ + "_" + std::to_string(next_session_number_++);
        auto session = std::make_shared<socks_session>(std::move(socket), configuration_, std::move(session_id));
        session->startup();
    }
}

redirect_service::redirect_service(tcp::acceptor acceptor, rv::app::config configuration, std::string service_id)
    : acceptor_(std::move(acceptor)), configuration_(std::move(configuration)), service_id_(std::move(service_id))
{
}

void redirect_service::startup()
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(acceptor_.get_executor(),
                          accept_connections(),
                          [self](const std::exception_ptr& exception)
                          {
                              log_service_exception(self->service_id_, exception);
                              self->shutdown();
                              static_cast<boost::asio::io_context&>(self->acceptor_.get_executor().context()).stop();
                          });
}

void redirect_service::shutdown()
{
    const auto self = shared_from_this();
    boost::asio::post(acceptor_.get_executor(),
                      [self]
                      {
                          if (self->stopping_)
                          {
                              return;
                          }
                          self->stopping_ = true;
                          boost::system::error_code ignored;
                          self->acceptor_.close(ignored);
                      });
}

boost::asio::awaitable<void> redirect_service::accept_connections()
{
    spdlog::info("redirect tcp proxy listening on 0.0.0.0:{} ({})", acceptor_.local_endpoint().port(), service_id_);
    for (;;)
    {
        auto socket = co_await acceptor_.async_accept(boost::asio::use_awaitable);
        auto session_id = service_id_ + "_" + std::to_string(next_session_number_++);
        auto session = std::make_shared<redirect_session>(std::move(socket), configuration_, std::move(session_id));
        session->startup();
    }
}

tcp_tproxy_service::tcp_tproxy_service(tcp::acceptor acceptor, rv::app::config configuration, std::string service_id)
    : acceptor_(std::move(acceptor)), configuration_(std::move(configuration)), service_id_(std::move(service_id))
{
}

void tcp_tproxy_service::startup()
{
    const auto self = shared_from_this();
    boost::asio::co_spawn(acceptor_.get_executor(),
                          accept_connections(),
                          [self](const std::exception_ptr& exception)
                          {
                              log_service_exception(self->service_id_, exception);
                              self->shutdown();
                              static_cast<boost::asio::io_context&>(self->acceptor_.get_executor().context()).stop();
                          });
}

void tcp_tproxy_service::shutdown()
{
    const auto self = shared_from_this();
    boost::asio::post(acceptor_.get_executor(),
                      [self]
                      {
                          if (self->stopping_)
                          {
                              return;
                          }
                          self->stopping_ = true;
                          boost::system::error_code ignored;
                          self->acceptor_.close(ignored);
                      });
}

boost::asio::awaitable<void> tcp_tproxy_service::accept_connections()
{
    spdlog::info("tproxy tcp proxy listening on 0.0.0.0:{} ({})", acceptor_.local_endpoint().port(), service_id_);
    for (;;)
    {
        auto socket = co_await acceptor_.async_accept(boost::asio::use_awaitable);
        auto session_id = service_id_ + "_" + std::to_string(next_session_number_++);
        auto session = std::make_shared<tcp_tproxy_session>(std::move(socket), configuration_, std::move(session_id));
        session->startup();
    }
}

}    // namespace rv::tcp_proxy

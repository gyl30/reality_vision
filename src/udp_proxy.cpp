#include "udp_proxy.hpp"

#include "reality_config.hpp"
#include "reality_stream.hpp"
#include "tcp_byte_stream.hpp"
#include "transparent.hpp"
#include "vless_header.hpp"
#include "vless_udp_stream.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <map>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace rv::udp_proxy
{
namespace
{

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr std::size_t max_udp_packet_size = 65535;
constexpr std::uint16_t deferred_udp_443_port = 443;
constexpr auto tproxy_udp_idle_timeout = std::chrono::seconds(120);
constexpr auto tproxy_udp_cleanup_interval = std::chrono::seconds(30);

struct proxy_target
{
    vless::address destination;
    std::uint16_t port{};
};

vless::address to_vless_address(const socks5::address& address)
{
    return std::visit(
        []<typename address_type>(const address_type& value) -> vless::address
        {
            if constexpr (std::is_same_v<address_type, socks5::ipv4_address>)
            {
                return vless::ipv4_address{value.bytes};
            }
            else if constexpr (std::is_same_v<address_type, socks5::ipv6_address>)
            {
                return vless::ipv6_address{value.bytes};
            }
            else
            {
                return vless::domain_address{value.name};
            }
        },
        address);
}

proxy_target make_proxy_target(const socks5::address& destination, const std::uint16_t port)
{
    return {
        .destination = to_vless_address(destination),
        .port = port,
    };
}

proxy_target make_proxy_target(const udp::endpoint& destination)
{
    return {
        .destination = vless::ipv4_address{destination.address().to_v4().to_bytes()},
        .port = destination.port(),
    };
}

std::string format_endpoint(const udp::endpoint& endpoint)
{
    return endpoint.address().to_string() + ":" + std::to_string(endpoint.port());
}

asio::awaitable<std::optional<reality::reality_stream>> connect_reality(const app::config& configuration,
                                                                         const std::string& session_id,
                                                                         boost::system::error_code& ec)
{
    const auto executor = co_await asio::this_coro::executor;
    auto tcp_stream = co_await net::tcp_byte_stream::connect(
        executor, configuration.reality_server_host, std::to_string(configuration.reality_server_port), session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    reality::client_config reality_configuration;
    reality_configuration.server_name = configuration.reality_server_name;
    reality_configuration.server_public_key = configuration.reality_server_public_key;
    reality_configuration.short_id = configuration.reality_short_id;
    co_return co_await reality::reality_stream::connect(std::move(*tcp_stream), std::move(reality_configuration), session_id, ec);
}

asio::awaitable<std::optional<vless::vless_udp_stream>> connect_udp_upstream(const app::config& configuration,
                                                                             const proxy_target& target,
                                                                             const std::string& session_id,
                                                                             boost::system::error_code& ec)
{
    auto reality_stream = co_await connect_reality(configuration, session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    vless::client_config vless_configuration;
    vless_configuration.user_id = configuration.vless_user_id;
    vless_configuration.destination = target.destination;
    vless_configuration.destination_port = target.port;
    co_return co_await vless::vless_udp_stream::connect(
        std::move(*reality_stream), std::move(vless_configuration), session_id, ec);
}

struct socks_udp_flow
{
    socks_udp_flow(vless::vless_udp_stream stream, socks5::address destination, const std::uint16_t port, std::string id)
        : upstream(std::move(stream)), remote_address(std::move(destination)), remote_port(port), session_id(std::move(id))
    {
    }

    vless::vless_udp_stream upstream;
    socks5::address remote_address;
    std::uint16_t remote_port{};
    std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};
    std::string session_id;
    bool closed{false};
};

struct socks_udp_state
{
    explicit socks_udp_state(udp::socket socket) : relay_socket(std::move(socket)) {}

    udp::socket relay_socket;
    std::optional<udp::endpoint> client_endpoint;
    std::map<std::string, std::shared_ptr<socks_udp_flow>> flows;
    bool closed{false};
    std::uint64_t next_flow_number{1};
};

void shutdown_socks_state(const std::shared_ptr<socks_udp_state>& state)
{
    state->closed = true;
    boost::system::error_code ignored;
    state->relay_socket.close(ignored);
    for (auto& [key, flow] : state->flows)
    {
        static_cast<void>(key);
        flow->closed = true;
        flow->upstream.shutdown();
    }
    state->flows.clear();
}

asio::awaitable<void> run_socks_downlink(std::shared_ptr<socks_udp_state> state, std::shared_ptr<socks_udp_flow> flow)
{
    for (;;)
    {
        boost::system::error_code ec;
        auto payload = co_await flow->upstream.read_datagram(ec);
        if (ec || !payload)
        {
            if (ec)
            {
                spdlog::warn("{} socks5 udp downlink read failed: {}", flow->session_id, ec.message());
            }
            flow->closed = true;
            co_return;
        }
        if (state->closed || !state->client_endpoint)
        {
            spdlog::warn("{} socks5 udp downlink stopped state_closed {} client_endpoint {}",
                         flow->session_id,
                         state->closed,
                         state->client_endpoint.has_value());
            co_return;
        }

        flow->last_activity = std::chrono::steady_clock::now();
        auto packet = socks5::encode_udp_datagram(flow->remote_address, flow->remote_port, *payload, ec);
        if (ec)
        {
            spdlog::warn("{} socks5 udp response encode failed: {}", flow->session_id, ec.message());
            flow->closed = true;
            flow->upstream.shutdown();
            co_return;
        }

        spdlog::info("{} socks5 udp downlink sending {} to {}",
                     flow->session_id,
                     packet.size(),
                     format_endpoint(*state->client_endpoint));
        co_await state->relay_socket.async_send_to(
            asio::buffer(packet), *state->client_endpoint, asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
        {
            spdlog::warn("{} socks5 udp downlink send failed: {}", flow->session_id, ec.message());
            flow->closed = true;
            flow->upstream.shutdown();
            co_return;
        }
        spdlog::info("{} socks5 udp downlink sent", flow->session_id);
    }
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
        spdlog::error("{} unexpected udp session exception: {}", session_id, error.what());
    }
    catch (...)
    {
        spdlog::error("{} unexpected non-standard udp session exception", session_id);
    }
}

asio::awaitable<std::shared_ptr<socks_udp_flow>> get_socks_flow(const std::shared_ptr<socks_udp_state>& state,
                                                                 const app::config& configuration,
                                                                 const socks5::udp_datagram& datagram,
                                                                 const std::string& association_id,
                                                                 boost::system::error_code& ec)
{
    const auto key = socks5::format_destination(datagram.destination, datagram.port);
    if (const auto iterator = state->flows.find(key); iterator != state->flows.end())
    {
        if (!iterator->second->closed)
        {
            co_return iterator->second;
        }
        iterator->second->upstream.shutdown();
        state->flows.erase(iterator);
    }

    const auto flow_id = association_id + "_udp_" + std::to_string(state->next_flow_number++);
    const auto target = make_proxy_target(datagram.destination, datagram.port);
    auto upstream = co_await connect_udp_upstream(configuration, target, flow_id, ec);
    if (ec)
    {
        co_return nullptr;
    }

    auto flow = std::make_shared<socks_udp_flow>(std::move(*upstream), datagram.destination, datagram.port, flow_id);
    state->flows.emplace(key, flow);
    spdlog::info("{} socks5 udp flow {}", flow_id, key);

    const auto executor = co_await asio::this_coro::executor;
    asio::co_spawn(executor,
                   run_socks_downlink(state, flow),
                   [flow_id](const std::exception_ptr& exception) { log_session_exception(flow_id, exception); });
    co_return flow;
}

asio::awaitable<void> wait_for_control_close(tcp::socket& control_socket, boost::system::error_code& ec)
{
    std::array<std::uint8_t, 1> buffer{};
    for (;;)
    {
        const auto count = co_await control_socket.async_read_some(asio::buffer(buffer), asio::redirect_error(asio::use_awaitable, ec));
        if (ec == asio::error::eof || (!ec && count == 0))
        {
            ec.clear();
            co_return;
        }
        if (ec)
        {
            co_return;
        }
    }
}

asio::awaitable<void> run_socks_udp_relay(const std::shared_ptr<socks_udp_state>& state,
                                           const app::config& configuration,
                                           const socks5::request& request,
                                           const udp::endpoint& tcp_peer,
                                           const std::string& session_id,
                                           boost::system::error_code& ec)
{
    std::array<std::uint8_t, max_udp_packet_size> buffer{};

    for (;;)
    {
        udp::endpoint source;
        const auto count = co_await state->relay_socket.async_receive_from(
            asio::buffer(buffer), source, asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }

        if (source.address() != tcp_peer.address())
        {
            continue;
        }
        if (request.port != 0 && source.port() != request.port)
        {
            continue;
        }
        if (!state->client_endpoint)
        {
            state->client_endpoint = source;
        }
        else if (source != *state->client_endpoint)
        {
            continue;
        }

        socks5::udp_datagram datagram;
        const auto packet_ec = socks5::decode_udp_datagram(std::span(buffer.data(), count), datagram);
        if (packet_ec)
        {
            continue;
        }
        if (datagram.port == deferred_udp_443_port)
        {
            spdlog::debug("{} socks5 udp/443 deferred", session_id);
            continue;
        }

        auto flow = co_await get_socks_flow(state, configuration, datagram, session_id, ec);
        if (ec)
        {
            spdlog::warn("{} socks5 udp upstream connection failed for {}: {}",
                         session_id,
                         socks5::format_destination(datagram.destination, datagram.port),
                         ec.message());
            ec.clear();
            continue;
        }

        flow->last_activity = std::chrono::steady_clock::now();
        co_await flow->upstream.write_datagram(datagram.payload, ec);
        if (ec)
        {
            spdlog::warn("{} socks5 udp uplink failed: {}", flow->session_id, ec.message());
            flow->closed = true;
            flow->upstream.shutdown();
            ec.clear();
        }
    }
}

struct tproxy_udp_flow
{
    tproxy_udp_flow(vless::vless_udp_stream stream,
                    udp::socket reply,
                    udp::endpoint source,
                    udp::endpoint destination,
                    std::string id)
        : upstream(std::move(stream)),
          reply_socket(std::move(reply)),
          client(std::move(source)),
          original_destination(std::move(destination)),
          session_id(std::move(id))
    {
    }

    vless::vless_udp_stream upstream;
    udp::socket reply_socket;
    udp::endpoint client;
    udp::endpoint original_destination;
    std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};
    std::string session_id;
    bool closed{false};
};

struct tproxy_udp_state
{
    explicit tproxy_udp_state(udp::socket listener) : socket(std::move(listener)) {}

    udp::socket socket;
    std::map<std::string, std::shared_ptr<tproxy_udp_flow>> flows;
    std::uint64_t next_flow_number{1};
    bool closed{false};
};

std::string tproxy_flow_key(const udp::endpoint& client, const udp::endpoint& destination)
{
    return format_endpoint(client) + "->" + format_endpoint(destination);
}

udp::socket create_transparent_reply_socket(asio::any_io_executor executor,
                                            const udp::endpoint& source,
                                            boost::system::error_code& ec)
{
    udp::socket socket(executor);
    socket.open(udp::v4(), ec);
    if (ec)
    {
        return socket;
    }

    socket.set_option(asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return socket;
    }

    ec = transparent::enable_ipv4_transparent(socket);
    if (ec)
    {
        return socket;
    }

    socket.bind(source, ec);
    return socket;
}

asio::awaitable<void> run_tproxy_downlink(std::shared_ptr<tproxy_udp_flow> flow)
{
    for (;;)
    {
        boost::system::error_code ec;
        auto payload = co_await flow->upstream.read_datagram(ec);
        if (ec || !payload)
        {
            flow->closed = true;
            co_return;
        }

        flow->last_activity = std::chrono::steady_clock::now();
        co_await flow->reply_socket.async_send_to(
            asio::buffer(*payload), flow->client, asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
        {
            flow->closed = true;
            flow->upstream.shutdown();
            co_return;
        }
    }
}

asio::awaitable<std::shared_ptr<tproxy_udp_flow>> get_tproxy_flow(const std::shared_ptr<tproxy_udp_state>& state,
                                                                   const app::config& configuration,
                                                                   const udp::endpoint& client,
                                                                   const udp::endpoint& destination,
                                                                   boost::system::error_code& ec)
{
    const auto key = tproxy_flow_key(client, destination);
    if (const auto iterator = state->flows.find(key); iterator != state->flows.end())
    {
        if (!iterator->second->closed)
        {
            co_return iterator->second;
        }
        iterator->second->upstream.shutdown();
        state->flows.erase(iterator);
    }

    const auto session_id = "tproxy_udp_" + std::to_string(state->next_flow_number++);
    const auto executor = co_await asio::this_coro::executor;
    auto reply_socket = create_transparent_reply_socket(executor, destination, ec);
    if (ec)
    {
        co_return nullptr;
    }

    auto upstream = co_await connect_udp_upstream(configuration, make_proxy_target(destination), session_id, ec);
    if (ec)
    {
        co_return nullptr;
    }

    auto flow = std::make_shared<tproxy_udp_flow>(
        std::move(*upstream), std::move(reply_socket), client, destination, session_id);
    state->flows.emplace(key, flow);
    spdlog::info("{} transparent udp {} -> {}", session_id, format_endpoint(client), format_endpoint(destination));

    asio::co_spawn(executor,
                   run_tproxy_downlink(flow),
                   [session_id](const std::exception_ptr& exception) { log_session_exception(session_id, exception); });
    co_return flow;
}

void cleanup_tproxy_flows(const std::shared_ptr<tproxy_udp_state>& state)
{
    const auto now = std::chrono::steady_clock::now();
    for (auto iterator = state->flows.begin(); iterator != state->flows.end();)
    {
        const auto& flow = iterator->second;
        if (flow->closed || now - flow->last_activity >= tproxy_udp_idle_timeout)
        {
            flow->closed = true;
            flow->upstream.shutdown();
            boost::system::error_code ignored;
            flow->reply_socket.close(ignored);
            iterator = state->flows.erase(iterator);
        }
        else
        {
            ++iterator;
        }
    }
}

asio::awaitable<void> run_tproxy_cleanup(std::shared_ptr<tproxy_udp_state> state)
{
    asio::steady_timer timer(co_await asio::this_coro::executor);
    while (!state->closed)
    {
        timer.expires_after(tproxy_udp_cleanup_interval);
        boost::system::error_code ec;
        co_await timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }
        cleanup_tproxy_flows(state);
    }
}

void shutdown_tproxy_state(const std::shared_ptr<tproxy_udp_state>& state)
{
    state->closed = true;
    boost::system::error_code ignored;
    state->socket.close(ignored);
    for (auto& [key, flow] : state->flows)
    {
        static_cast<void>(key);
        flow->closed = true;
        flow->upstream.shutdown();
        flow->reply_socket.close(ignored);
    }
    state->flows.clear();
}

}    // namespace

asio::awaitable<void> run_socks_association(tcp::socket control_socket,
                                             app::config configuration,
                                             socks5::request request,
                                             std::string session_id)
{
    boost::system::error_code ec;
    udp::socket relay_socket(control_socket.get_executor());
    relay_socket.open(udp::v4(), ec);
    if (ec)
    {
        boost::system::error_code ignored;
        co_await socks5::send_reply(control_socket, socks5::reply::general_failure, ignored);
        co_return;
    }
    relay_socket.bind(udp::endpoint(asio::ip::address_v4::loopback(), 0), ec);
    if (ec)
    {
        boost::system::error_code ignored;
        co_await socks5::send_reply(control_socket, socks5::reply::general_failure, ignored);
        co_return;
    }

    const auto relay_endpoint = relay_socket.local_endpoint(ec);
    if (ec)
    {
        co_return;
    }
    co_await socks5::send_reply(control_socket, socks5::reply::succeeded, relay_endpoint, ec);
    if (ec)
    {
        co_return;
    }

    const auto tcp_peer = control_socket.remote_endpoint(ec);
    if (ec || !tcp_peer.address().is_v4())
    {
        co_return;
    }

    spdlog::info("{} socks5 udp association on {}", session_id, format_endpoint(relay_endpoint));
    auto state = std::make_shared<socks_udp_state>(std::move(relay_socket));

    using namespace asio::experimental::awaitable_operators;    // NOLINT
    boost::system::error_code control_ec;
    boost::system::error_code relay_ec;
    co_await (wait_for_control_close(control_socket, control_ec) ||
              run_socks_udp_relay(state,
                                  configuration,
                                  request,
                                  udp::endpoint(tcp_peer.address(), tcp_peer.port()),
                                  session_id,
                                  relay_ec));

    spdlog::warn("{} socks5 udp association race completed control_ec {} relay_ec {}",
                 session_id,
                 control_ec.message(),
                 relay_ec.message());
    shutdown_socks_state(state);
    boost::system::error_code ignored;
    control_socket.close(ignored);

    if (relay_ec && relay_ec != asio::error::operation_aborted)
    {
        spdlog::warn("{} socks5 udp association failed: {}", session_id, relay_ec.message());
        co_return;
    }
    if (control_ec && control_ec != asio::error::operation_aborted)
    {
        spdlog::warn("{} socks5 udp control failed: {}", session_id, control_ec.message());
        co_return;
    }
    spdlog::info("{} socks5 udp association completed", session_id);
}

udp::socket create_tproxy_socket(asio::any_io_executor executor, const std::uint16_t port, boost::system::error_code& ec)
{
    udp::socket socket(executor);
    socket.open(udp::v4(), ec);
    if (ec)
    {
        return socket;
    }

    socket.set_option(asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return socket;
    }

    ec = transparent::enable_ipv4_transparent(socket);
    if (ec)
    {
        return socket;
    }
    ec = transparent::enable_ipv4_original_destination(socket);
    if (ec)
    {
        return socket;
    }

    socket.bind(udp::endpoint(udp::v4(), port), ec);
    return socket;
}

asio::awaitable<void> run_tproxy_server(udp::socket socket, app::config configuration, boost::system::error_code& ec)
{
    const auto executor = co_await asio::this_coro::executor;
    const auto listen_port = socket.local_endpoint(ec).port();
    if (ec)
    {
        co_return;
    }

    spdlog::info("tproxy udp proxy listening on 0.0.0.0:{}", listen_port);
    auto state = std::make_shared<tproxy_udp_state>(std::move(socket));
    asio::co_spawn(executor,
                   run_tproxy_cleanup(state),
                   [](const std::exception_ptr& exception) { log_session_exception("tproxy_udp_cleanup", exception); });

    std::array<std::uint8_t, max_udp_packet_size> buffer{};
    for (;;)
    {
        co_await state->socket.async_wait(udp::socket::wait_read, asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
        {
            shutdown_tproxy_state(state);
            co_return;
        }

        udp::endpoint client;
        udp::endpoint destination;
        const auto count = transparent::receive_ipv4_original_datagram(state->socket, buffer, client, destination, ec);
        if (ec)
        {
            shutdown_tproxy_state(state);
            co_return;
        }
        if (!count)
        {
            continue;
        }
        if (destination.port() == deferred_udp_443_port)
        {
            spdlog::debug("tproxy udp/443 deferred {} -> {}", format_endpoint(client), format_endpoint(destination));
            continue;
        }

        auto flow = co_await get_tproxy_flow(state, configuration, client, destination, ec);
        if (ec)
        {
            spdlog::warn("tproxy udp upstream connection failed for {} -> {}: {}",
                         format_endpoint(client),
                         format_endpoint(destination),
                         ec.message());
            ec.clear();
            continue;
        }

        flow->last_activity = std::chrono::steady_clock::now();
        co_await flow->upstream.write_datagram(std::span(buffer.data(), *count), ec);
        if (ec)
        {
            spdlog::warn("{} udp uplink failed: {}", flow->session_id, ec.message());
            flow->closed = true;
            flow->upstream.shutdown();
            ec.clear();
        }
    }
}

}    // namespace rv::udp_proxy

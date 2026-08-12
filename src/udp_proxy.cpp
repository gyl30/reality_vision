#include "udp_proxy.hpp"

#include "network_address.hpp"
#include "proxy_common.hpp"

#include "runtime_state.hpp"
#include "transparent.hpp"
#include "vless_header.hpp"
#include "vless_udp_stream.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/asio/experimental/channel.hpp>
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

#include <sys/socket.h>

namespace rv::udp_proxy
{
namespace
{

namespace asio = boost::asio;
using tcp = asio::ip::tcp;
using udp = asio::ip::udp;

constexpr std::size_t kMaxUdpPacketSize = 65535;
constexpr std::size_t kUdpFlowQueueCapacity = 16;
constexpr std::size_t kMaximumSocksFlowsPerAssociation = 256;
constexpr auto kUdpFlowIdleTimeout = std::chrono::seconds(120);
constexpr auto kUdpFlowCleanupInterval = std::chrono::seconds(30);

using udp_payload_channel = asio::experimental::channel<void(boost::system::error_code, std::vector<std::uint8_t>)>;

class udp_flow_registration
{
   public:
    udp_flow_registration(std::shared_ptr<app::runtime_state> runtime, const std::size_t maximum)
        : runtime_(std::move(runtime)), acquired_(runtime_->try_acquire_udp(maximum))
    {
    }

    udp_flow_registration(udp_flow_registration&& other) noexcept
        : runtime_(std::move(other.runtime_)), acquired_(std::exchange(other.acquired_, false))
    {
    }
    udp_flow_registration& operator=(udp_flow_registration&&) = delete;
    udp_flow_registration(const udp_flow_registration&) = delete;
    udp_flow_registration& operator=(const udp_flow_registration&) = delete;

    bool acquired() const noexcept { return acquired_; }

    ~udp_flow_registration()
    {
        if (acquired_)
        {
            runtime_->release_udp();
        }
    }

   private:
    std::shared_ptr<app::runtime_state> runtime_;
    bool acquired_{};
};

template <typename State, typename CloseFlow>
asio::awaitable<void> run_udp_flow_cleanup(std::shared_ptr<State> state, CloseFlow close_flow)
{
    while (!state->closed)
    {
        state->cleanup_timer.expires_after(kUdpFlowCleanupInterval);
        boost::system::error_code ec;
        co_await state->cleanup_timer.async_wait(asio::redirect_error(asio::use_awaitable, ec));
        if (ec || state->closed)
        {
            co_return;
        }

        const auto now = std::chrono::steady_clock::now();
        for (auto iterator = state->flows.begin(); iterator != state->flows.end();)
        {
            auto& flow = *iterator->second;
            if (flow.closed || now - flow.last_activity >= kUdpFlowIdleTimeout)
            {
                close_flow(flow);
                iterator = state->flows.erase(iterator);
            }
            else
            {
                ++iterator;
            }
        }
    }
}

proxy::target make_proxy_target(const net::address& destination, const std::uint16_t port)
{
    return {
        .destination = destination,
        .port = port,
    };
}

proxy::target make_proxy_target(const udp::endpoint& destination)
{
    return {
        .destination = net::ipv4_address{destination.address().to_v4().to_bytes()},
        .port = destination.port(),
    };
}

std::string socks_flow_key(const net::address& destination, const std::uint16_t port)
{
    std::string key;
    key.push_back(static_cast<char>(destination.index()));
    std::visit(
        [&key](const auto& value)
        {
            using address_type = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<address_type, net::domain_address>)
            {
                key.append(value.name);
            }
            else
            {
                for (const auto byte : value.bytes)
                {
                    key.push_back(static_cast<char>(byte));
                }
            }
        },
        destination);
    key.push_back(static_cast<char>(port >> 8U));
    key.push_back(static_cast<char>(port));
    return key;
}

std::string format_endpoint(const udp::endpoint& endpoint) { return endpoint.address().to_string() + ":" + std::to_string(endpoint.port()); }

asio::awaitable<std::optional<vless::vless_udp_stream>> connect_udp_upstream(const app::config& configuration,
                                                                             std::shared_ptr<app::runtime_state> runtime,
                                                                             const proxy::target& target,
                                                                             const std::string& session_id,
                                                                             boost::system::error_code& ec)
{
    auto reality_stream = co_await proxy::connect_reality(configuration, std::move(runtime), session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    vless::client_config vless_configuration;
    vless_configuration.user_id = configuration.vless_user_id;
    vless_configuration.destination = target.destination;
    vless_configuration.destination_port = target.port;
    co_return co_await vless::vless_udp_stream::connect(std::move(*reality_stream), std::move(vless_configuration), session_id, ec);
}

struct socks_udp_flow
{
    udp_flow_registration registration;
    std::optional<vless::vless_udp_stream> upstream;
    udp_payload_channel uplink;
    net::address remote_address;
    std::uint16_t remote_port{};
    std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};
    std::string session_id;
    std::string key;
    bool closed{false};
};

struct socks_udp_state
{
    udp::socket relay_socket;
    asio::steady_timer cleanup_timer;
    std::shared_ptr<app::runtime_state> runtime;
    std::optional<udp::endpoint> client_endpoint{};
    std::map<std::string, std::shared_ptr<socks_udp_flow>> flows{};
    std::uint64_t next_flow_number{1};
    bool closed{false};
};

void close_socks_flow(socks_udp_flow& flow)
{
    if (flow.closed)
    {
        return;
    }

    flow.closed = true;
    flow.uplink.close();
    if (flow.upstream)
    {
        flow.upstream->shutdown();
    }
}

void shutdown_socks_state(const std::shared_ptr<socks_udp_state>& state)
{
    if (state->closed)
    {
        return;
    }

    state->closed = true;
    boost::system::error_code ignored;
    state->relay_socket.close(ignored);
    for (auto& [key, flow] : state->flows)
    {
        static_cast<void>(key);
        close_socks_flow(*flow);
    }
    state->flows.clear();
    static_cast<void>(state->cleanup_timer.cancel());
}

asio::awaitable<void> run_socks_downlink(std::shared_ptr<socks_udp_state> state, std::shared_ptr<socks_udp_flow> flow)
{
    for (;;)
    {
        boost::system::error_code ec;
        auto payload = co_await flow->upstream->read_datagram(ec);
        if (ec)
        {
            if (ec != asio::error::operation_aborted)
            {
                spdlog::warn("{} socks5 udp downlink read failed: {}", flow->session_id, ec.message());
            }
            close_socks_flow(*flow);
            co_return;
        }
        if (state->closed || flow->closed)
        {
            co_return;
        }

        flow->last_activity = std::chrono::steady_clock::now();
        auto packet = socks5::encode_udp_datagram(flow->remote_address, flow->remote_port, payload, ec);
        if (ec)
        {
            spdlog::warn("{} socks5 udp response encode failed: {}", flow->session_id, ec.message());
            close_socks_flow(*flow);
            co_return;
        }

        co_await state->relay_socket.async_send_to(asio::buffer(packet), *state->client_endpoint, asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
        {
            if (ec != asio::error::operation_aborted)
            {
                spdlog::warn("{} socks5 udp downlink send failed: {}", flow->session_id, ec.message());
            }
            close_socks_flow(*flow);
            co_return;
        }
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

asio::awaitable<void> run_socks_flow(std::shared_ptr<socks_udp_state> state,
                                     std::shared_ptr<socks_udp_flow> flow,
                                     app::config configuration,
                                     proxy::target target)
{
    boost::system::error_code ec;
    auto upstream = co_await connect_udp_upstream(configuration, state->runtime, target, flow->session_id, ec);
    if (ec)
    {
        spdlog::warn("{} socks5 udp upstream connection failed for {}: {}",
                     flow->session_id,
                     net::format_address_port(flow->remote_address, flow->remote_port),
                     ec.message());
    }
    else if (!state->closed && !flow->closed)
    {
        flow->upstream.emplace(std::move(*upstream));
        spdlog::info("{} socks5 udp flow {}", flow->session_id, net::format_address_port(flow->remote_address, flow->remote_port));

        const auto executor = co_await asio::this_coro::executor;
        asio::co_spawn(executor,
                       run_socks_downlink(state, flow),
                       [flow](const std::exception_ptr& exception)
                       {
                           if (exception)
                           {
                               log_session_exception(flow->session_id, exception);
                               close_socks_flow(*flow);
                           }
                       });

        for (;;)
        {
            auto payload = co_await flow->uplink.async_receive(asio::redirect_error(asio::use_awaitable, ec));
            if (ec || flow->closed)
            {
                break;
            }

            flow->last_activity = std::chrono::steady_clock::now();
            co_await flow->upstream->write_datagram(payload, ec);
            if (ec)
            {
                spdlog::warn("{} socks5 udp uplink failed: {}", flow->session_id, ec.message());
                break;
            }
        }
    }
    else
    {
        upstream->shutdown();
    }

    close_socks_flow(*flow);
    if (const auto iterator = state->flows.find(flow->key); iterator != state->flows.end() && iterator->second == flow)
    {
        state->flows.erase(iterator);
    }
}

std::shared_ptr<socks_udp_flow> get_socks_flow(const std::shared_ptr<socks_udp_state>& state,
                                               const app::config& configuration,
                                               const socks5::udp_datagram& datagram,
                                               const std::string& association_id)
{
    const auto key = socks_flow_key(datagram.destination, datagram.port);
    if (const auto iterator = state->flows.find(key); iterator != state->flows.end())
    {
        if (!iterator->second->closed)
        {
            return iterator->second;
        }
        close_socks_flow(*iterator->second);
        state->flows.erase(iterator);
    }
    if (state->flows.size() >= kMaximumSocksFlowsPerAssociation)
    {
        return nullptr;
    }

    auto registration = udp_flow_registration(state->runtime, configuration.maximum_udp_flows);
    if (!registration.acquired())
    {
        return nullptr;
    }

    const auto flow_id = association_id + "_udp_" + std::to_string(state->next_flow_number++);
    const auto target = make_proxy_target(datagram.destination, datagram.port);
    const auto executor = state->relay_socket.get_executor();

    auto flow = std::make_shared<socks_udp_flow>(socks_udp_flow{
        .registration = std::move(registration),
        .upstream = std::nullopt,
        .uplink = udp_payload_channel(executor, kUdpFlowQueueCapacity),
        .remote_address = datagram.destination,
        .remote_port = datagram.port,
        .session_id = flow_id,
        .key = key,
    });
    state->flows.emplace(key, flow);
    asio::co_spawn(executor,
                   run_socks_flow(state, flow, configuration, target),
                   [flow](const std::exception_ptr& exception)
                   {
                       if (exception)
                       {
                           log_session_exception(flow->session_id, exception);
                           close_socks_flow(*flow);
                       }
                   });
    return flow;
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
    std::array<std::uint8_t, kMaxUdpPacketSize> buffer{};

    for (;;)
    {
        udp::endpoint source;
        const auto count =
            co_await state->relay_socket.async_receive_from(asio::buffer(buffer), source, asio::redirect_error(asio::use_awaitable, ec));
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
        socks5::udp_datagram datagram;
        const auto packet_ec = socks5::decode_udp_datagram(std::span(buffer.data(), count), datagram);
        if (packet_ec)
        {
            continue;
        }
        if (datagram.payload.empty())
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
        auto flow = get_socks_flow(state, configuration, datagram, session_id);
        if (!flow)
        {
            continue;
        }
        auto payload = std::vector<std::uint8_t>(datagram.payload.begin(), datagram.payload.end());
        if (flow->uplink.try_send(boost::system::error_code{}, std::move(payload)))
        {
            flow->last_activity = std::chrono::steady_clock::now();
        }
    }
}

struct tproxy_udp_flow
{
    udp_flow_registration registration;
    std::optional<vless::vless_udp_stream> upstream;
    udp_payload_channel uplink;
    udp::socket reply_socket;
    udp::endpoint client;
    udp::endpoint destination;
    std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};
    std::string session_id;
    std::string key;
    bool closed{false};
};

struct tproxy_udp_state
{
    udp::socket socket;
    asio::steady_timer cleanup_timer;
    std::shared_ptr<app::runtime_state> runtime;
    std::map<std::string, std::shared_ptr<tproxy_udp_flow>> flows{};
    std::uint64_t next_flow_number{1};
    bool closed{false};
};

std::string tproxy_flow_key(const udp::endpoint& client, const udp::endpoint& destination)
{
    return format_endpoint(client) + "->" + format_endpoint(destination);
}

udp::socket create_transparent_reply_socket(asio::any_io_executor executor, const udp::endpoint& source, boost::system::error_code& ec)
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

void close_tproxy_flow(tproxy_udp_flow& flow)
{
    if (flow.closed)
    {
        return;
    }

    flow.closed = true;
    flow.uplink.close();
    if (flow.upstream)
    {
        flow.upstream->shutdown();
    }
    boost::system::error_code ignored;
    flow.reply_socket.close(ignored);
}

asio::awaitable<void> run_tproxy_downlink(std::shared_ptr<tproxy_udp_flow> flow)
{
    for (;;)
    {
        boost::system::error_code ec;
        auto payload = co_await flow->upstream->read_datagram(ec);
        if (ec)
        {
            if (ec != asio::error::operation_aborted)
            {
                spdlog::warn("{} tproxy udp downlink read failed: {}", flow->session_id, ec.message());
            }
            close_tproxy_flow(*flow);
            co_return;
        }
        if (flow->closed)
        {
            co_return;
        }

        flow->last_activity = std::chrono::steady_clock::now();
        co_await flow->reply_socket.async_send_to(asio::buffer(payload), flow->client, asio::redirect_error(asio::use_awaitable, ec));
        if (ec)
        {
            if (ec != asio::error::operation_aborted)
            {
                spdlog::warn("{} tproxy udp downlink send failed: {}", flow->session_id, ec.message());
            }
            close_tproxy_flow(*flow);
            co_return;
        }
    }
}

asio::awaitable<void> run_tproxy_flow(std::shared_ptr<tproxy_udp_state> state, std::shared_ptr<tproxy_udp_flow> flow, app::config configuration)
{
    boost::system::error_code ec;
    auto upstream = co_await connect_udp_upstream(configuration, state->runtime, make_proxy_target(flow->destination), flow->session_id, ec);
    if (ec)
    {
        spdlog::warn("{} tproxy udp upstream connection failed for {} -> {}: {}",
                     flow->session_id,
                     format_endpoint(flow->client),
                     format_endpoint(flow->destination),
                     ec.message());
    }
    else if (!state->closed && !flow->closed)
    {
        flow->upstream.emplace(std::move(*upstream));
        spdlog::info("{} transparent udp {} -> {}", flow->session_id, format_endpoint(flow->client), format_endpoint(flow->destination));

        const auto executor = co_await asio::this_coro::executor;
        asio::co_spawn(executor,
                       run_tproxy_downlink(flow),
                       [flow](const std::exception_ptr& exception)
                       {
                           if (exception)
                           {
                               log_session_exception(flow->session_id, exception);
                               close_tproxy_flow(*flow);
                           }
                       });

        for (;;)
        {
            auto payload = co_await flow->uplink.async_receive(asio::redirect_error(asio::use_awaitable, ec));
            if (ec || flow->closed)
            {
                break;
            }

            flow->last_activity = std::chrono::steady_clock::now();
            co_await flow->upstream->write_datagram(payload, ec);
            if (ec)
            {
                spdlog::warn("{} udp uplink failed: {}", flow->session_id, ec.message());
                break;
            }
        }
    }
    else
    {
        upstream->shutdown();
    }

    close_tproxy_flow(*flow);
    if (const auto iterator = state->flows.find(flow->key); iterator != state->flows.end() && iterator->second == flow)
    {
        state->flows.erase(iterator);
    }
}

std::shared_ptr<tproxy_udp_flow> get_tproxy_flow(const std::shared_ptr<tproxy_udp_state>& state,
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
            return iterator->second;
        }
        close_tproxy_flow(*iterator->second);
        state->flows.erase(iterator);
    }
    const auto session_id = "tproxy_udp_" + std::to_string(state->next_flow_number++);
    const auto executor = state->socket.get_executor();
    auto reply_socket = create_transparent_reply_socket(executor, destination, ec);
    if (ec)
    {
        spdlog::warn(
            "{} tproxy udp reply socket failed for {} -> {}: {}", session_id, format_endpoint(client), format_endpoint(destination), ec.message());
        return nullptr;
    }

    auto registration = udp_flow_registration(state->runtime, configuration.maximum_udp_flows);
    if (!registration.acquired())
    {
        return nullptr;
    }

    auto flow = std::make_shared<tproxy_udp_flow>(tproxy_udp_flow{
        .registration = std::move(registration),
        .upstream = std::nullopt,
        .uplink = udp_payload_channel(executor, kUdpFlowQueueCapacity),
        .reply_socket = std::move(reply_socket),
        .client = client,
        .destination = destination,
        .session_id = session_id,
        .key = key,
    });
    state->flows.emplace(key, flow);
    asio::co_spawn(executor,
                   run_tproxy_flow(state, flow, configuration),
                   [flow](const std::exception_ptr& exception)
                   {
                       if (exception)
                       {
                           log_session_exception(flow->session_id, exception);
                           close_tproxy_flow(*flow);
                       }
                   });
    return flow;
}

void shutdown_tproxy_state(const std::shared_ptr<tproxy_udp_state>& state)
{
    if (state->closed)
    {
        return;
    }

    state->closed = true;
    boost::system::error_code ignored;
    state->socket.close(ignored);
    for (auto& [key, flow] : state->flows)
    {
        static_cast<void>(key);
        close_tproxy_flow(*flow);
    }
    state->flows.clear();
    static_cast<void>(state->cleanup_timer.cancel());
}

}    // namespace

asio::awaitable<void> run_socks_association(tcp::socket control_socket,
                                            app::config configuration,
                                            std::shared_ptr<app::runtime_state> runtime,
                                            socks5::request request,
                                            std::string session_id)
{
    boost::system::error_code ec;
    udp::socket relay_socket(control_socket.get_executor());
    relay_socket.open(udp::v4(), ec);
    if (ec)
    {
        boost::system::error_code ignored;
        co_await socks5::send_reply(control_socket, socks5::reply::kGeneralFailure, ignored);
        co_return;
    }
    relay_socket.bind(udp::endpoint(asio::ip::address_v4::loopback(), 0), ec);
    if (ec)
    {
        boost::system::error_code ignored;
        co_await socks5::send_reply(control_socket, socks5::reply::kGeneralFailure, ignored);
        co_return;
    }

    const auto relay_endpoint = relay_socket.local_endpoint(ec);
    if (ec)
    {
        co_return;
    }
    co_await socks5::send_reply(control_socket, socks5::reply::kSucceeded, relay_endpoint, ec);
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
    const auto executor = relay_socket.get_executor();
    auto state = std::make_shared<socks_udp_state>(socks_udp_state{
        .relay_socket = std::move(relay_socket),
        .cleanup_timer = asio::steady_timer(executor),
        .runtime = std::move(runtime),
    });
    asio::co_spawn(executor,
                   run_udp_flow_cleanup(state, close_socks_flow),
                   [session_id](const std::exception_ptr& exception) { log_session_exception(session_id + "_udp_cleanup", exception); });

    using namespace asio::experimental::awaitable_operators;    // NOLINT
    boost::system::error_code control_ec;
    boost::system::error_code relay_ec;
    co_await (wait_for_control_close(control_socket, control_ec) ||
              run_socks_udp_relay(state, configuration, request, udp::endpoint(tcp_peer.address(), tcp_peer.port()), session_id, relay_ec));

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

udp::socket create_tproxy_socket(asio::any_io_executor executor,
                                 const std::uint16_t port,
                                 const bool enable_reuse_port,
                                 boost::system::error_code& ec)
{
    udp::socket socket(executor);
    socket.open(udp::v4(), ec);
    if (ec)
    {
        return socket;
    }

    const int reuse_port = 1;
    if (enable_reuse_port && ::setsockopt(socket.native_handle(), SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::generic_category());
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

asio::awaitable<void> run_tproxy_server(udp::socket socket,
                                        app::config configuration,
                                        std::shared_ptr<app::runtime_state> runtime,
                                        const std::size_t worker_index)
{
    boost::system::error_code ec;
    const auto executor = co_await asio::this_coro::executor;
    const auto listen_port = socket.local_endpoint(ec).port();
    if (ec)
    {
        co_return;
    }

    spdlog::info("tproxy udp proxy listening on 0.0.0.0:{} (worker {})", listen_port, worker_index);
    auto state = std::make_shared<tproxy_udp_state>(tproxy_udp_state{
        .socket = std::move(socket),
        .cleanup_timer = asio::steady_timer(executor),
        .runtime = std::move(runtime),
    });
    asio::co_spawn(executor,
                   run_udp_flow_cleanup(state, close_tproxy_flow),
                   [](const std::exception_ptr& exception) { log_session_exception("tproxy_udp_cleanup", exception); });

    std::array<std::uint8_t, kMaxUdpPacketSize> buffer{};
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
        if (!count || *count == 0)
        {
            continue;
        }
        auto flow = get_tproxy_flow(state, configuration, client, destination, ec);
        if (ec || !flow)
        {
            ec.clear();
            continue;
        }

        auto payload = std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*count));
        if (flow->uplink.try_send(boost::system::error_code{}, std::move(payload)))
        {
            flow->last_activity = std::chrono::steady_clock::now();
        }
    }
}

}    // namespace rv::udp_proxy

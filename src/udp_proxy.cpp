#include <map>
#include <span>
#include <array>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <optional>
#include <type_traits>
#include <sys/socket.h>

#include <spdlog/spdlog.h>
#include <boost/asio/post.hpp>
#include <boost/asio/buffer.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "udp_proxy.hpp"
#include "transparent.hpp"
#include "proxy_common.hpp"
#include "network_address.hpp"

namespace rv::udp_proxy
{
namespace
{

using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;

constexpr std::size_t kMaxUdpPacketSize = 65535;
constexpr std::size_t kUdpFlowQueueCapacity = 16;
constexpr std::size_t kMaximumSocksFlowsPerAssociation = 256;
constexpr auto kUdpFlowIdleTimeout = std::chrono::seconds(120);
constexpr auto kUdpFlowCleanupInterval = std::chrono::seconds(30);

using udp_payload_channel = boost::asio::experimental::channel<void(boost::system::error_code, std::vector<std::uint8_t>)>;

template <typename State, typename CloseFlow>
boost::asio::awaitable<void> run_udp_flow_cleanup(std::shared_ptr<State> state, CloseFlow close_flow)
{
    while (!state->closed)
    {
        state->cleanup_timer.expires_after(kUdpFlowCleanupInterval);
        boost::system::error_code ec;
        co_await state->cleanup_timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
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

struct socks_udp_flow
{
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
    boost::asio::steady_timer cleanup_timer;
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

boost::asio::awaitable<void> run_socks_downlink(std::shared_ptr<socks_udp_state> state, std::shared_ptr<socks_udp_flow> flow)
{
    for (;;)
    {
        boost::system::error_code ec;
        auto payload = co_await flow->upstream->read_datagram(ec);
        if (ec)
        {
            if (ec != boost::asio::error::operation_aborted)
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

        co_await state->relay_socket.async_send_to(
            boost::asio::buffer(packet), *state->client_endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (ec != boost::asio::error::operation_aborted)
            {
                spdlog::warn("{} socks5 udp downlink send failed: {}", flow->session_id, ec.message());
            }
            close_socks_flow(*flow);
            co_return;
        }
    }
}

boost::asio::awaitable<void> run_socks_flow(std::shared_ptr<socks_udp_state> state,
                                            std::shared_ptr<socks_udp_flow> flow,
                                            app::config configuration,
                                            proxy::target target)
{
    boost::system::error_code ec;
    auto upstream = co_await proxy::connect_udp(configuration, target, flow->session_id, ec);
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

        const auto executor = co_await boost::asio::this_coro::executor;
        boost::asio::co_spawn(executor, run_socks_downlink(state, flow), boost::asio::detached);

        for (;;)
        {
            auto payload = co_await flow->uplink.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
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

    const auto flow_id = association_id + "_udp_" + std::to_string(state->next_flow_number++);
    const auto target = make_proxy_target(datagram.destination, datagram.port);
    const auto executor = state->relay_socket.get_executor();

    auto flow = std::make_shared<socks_udp_flow>(socks_udp_flow{
        .upstream = std::nullopt,
        .uplink = udp_payload_channel(executor, kUdpFlowQueueCapacity),
        .remote_address = datagram.destination,
        .remote_port = datagram.port,
        .session_id = flow_id,
        .key = key,
    });
    state->flows.emplace(key, flow);
    boost::asio::co_spawn(executor, run_socks_flow(state, flow, configuration, target), boost::asio::detached);
    return flow;
}

boost::asio::awaitable<void> wait_for_control_close(tcp::socket& control_socket, boost::system::error_code& ec)
{
    std::array<std::uint8_t, 1> buffer{};
    for (;;)
    {
        const auto count =
            co_await control_socket.async_read_some(boost::asio::buffer(buffer), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::eof || (!ec && count == 0))
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

boost::asio::awaitable<void> run_socks_udp_relay(const std::shared_ptr<socks_udp_state>& state,
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
        const auto count = co_await state->relay_socket.async_receive_from(
            boost::asio::buffer(buffer), source, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
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

std::string tproxy_flow_key(const udp::endpoint& client, const udp::endpoint& destination)
{
    return format_endpoint(client) + "->" + format_endpoint(destination);
}

udp::socket create_transparent_reply_socket(boost::asio::any_io_executor executor, const udp::endpoint& source, boost::system::error_code& ec)
{
    udp::socket socket(executor);
    socket.open(udp::v4(), ec);
    if (ec)
    {
        return socket;
    }

    socket.set_option(boost::asio::socket_base::reuse_address(true), ec);
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

}    // namespace

class udp_tproxy_session final : public std::enable_shared_from_this<udp_tproxy_session>
{
   public:
    udp_tproxy_session(udp::socket reply_socket, udp::endpoint client, udp::endpoint destination, app::config configuration, std::string session_id)
        : uplink_(reply_socket.get_executor(), kUdpFlowQueueCapacity),
          idle_timer_(reply_socket.get_executor()),
          reply_socket_(std::move(reply_socket)),
          client_(std::move(client)),
          destination_(std::move(destination)),
          configuration_(std::move(configuration)),
          session_id_(std::move(session_id))
    {
    }

    void startup()
    {
        boost::asio::co_spawn(reply_socket_.get_executor(), run(), boost::asio::detached);
        boost::asio::co_spawn(reply_socket_.get_executor(), run_idle_timer(), boost::asio::detached);
    }

   private:
    void shutdown()
    {
        const auto self = shared_from_this();
        boost::asio::post(reply_socket_.get_executor(),
                          [self]
                          {
                              if (self->stopping_)
                              {
                                  return;
                              }
                              self->stopping_ = true;
                              self->close_resources();
                          });
    }

    void close_resources()
    {
        uplink_.close();
        if (upstream_)
        {
            upstream_->shutdown();
        }
        boost::system::error_code ignored;
        reply_socket_.close(ignored);
        static_cast<void>(idle_timer_.cancel());
    }

   public:
    bool send(std::vector<std::uint8_t> payload)
    {
        if (!uplink_.try_send(boost::system::error_code{}, std::move(payload)))
        {
            return false;
        }
        idle_timer_.expires_after(kUdpFlowIdleTimeout);
        return true;
    }

    bool stopped() const noexcept { return stopping_; }

   private:
    boost::asio::awaitable<void> run()
    {
        const auto self = shared_from_this();
        static_cast<void>(self);
        boost::system::error_code ec;
        auto upstream = co_await proxy::connect_udp(configuration_, make_proxy_target(destination_), session_id_, ec);
        if (ec)
        {
            spdlog::warn("{} tproxy udp upstream connection failed for {} -> {}: {}",
                         session_id_,
                         format_endpoint(client_),
                         format_endpoint(destination_),
                         ec.message());
            shutdown();
            co_return;
        }
        if (stopping_)
        {
            upstream->shutdown();
            co_return;
        }

        upstream_.emplace(std::move(*upstream));
        spdlog::info("{} transparent udp {} -> {}", session_id_, format_endpoint(client_), format_endpoint(destination_));

        boost::asio::co_spawn(reply_socket_.get_executor(), run_downlink(), boost::asio::detached);

        while (!stopping_)
        {
            auto payload = co_await uplink_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec || stopping_)
            {
                break;
            }

            co_await upstream_->write_datagram(payload, ec);
            if (ec)
            {
                spdlog::warn("{} udp uplink failed: {}", session_id_, ec.message());
                break;
            }
        }
        shutdown();
    }

    boost::asio::awaitable<void> run_downlink()
    {
        const auto self = shared_from_this();
        static_cast<void>(self);
        for (;;)
        {
            boost::system::error_code ec;
            auto payload = co_await upstream_->read_datagram(ec);
            if (ec)
            {
                if (ec != boost::asio::error::operation_aborted)
                {
                    spdlog::warn("{} tproxy udp downlink read failed: {}", session_id_, ec.message());
                }
                shutdown();
                co_return;
            }
            if (stopping_)
            {
                co_return;
            }

            idle_timer_.expires_after(kUdpFlowIdleTimeout);
            co_await reply_socket_.async_send_to(boost::asio::buffer(payload), client_, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (ec)
            {
                if (ec != boost::asio::error::operation_aborted)
                {
                    spdlog::warn("{} tproxy udp downlink send failed: {}", session_id_, ec.message());
                }
                shutdown();
                co_return;
            }
        }
    }

    boost::asio::awaitable<void> run_idle_timer()
    {
        const auto self = shared_from_this();
        static_cast<void>(self);
        while (!stopping_)
        {
            idle_timer_.expires_after(kUdpFlowIdleTimeout);
            boost::system::error_code ec;
            co_await idle_timer_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
            if (stopping_)
            {
                co_return;
            }
            if (ec == boost::asio::error::operation_aborted)
            {
                continue;
            }
            if (ec)
            {
                shutdown();
                co_return;
            }
            shutdown();
            co_return;
        }
    }

    std::optional<vless::vless_udp_stream> upstream_;
    udp_payload_channel uplink_;
    boost::asio::steady_timer idle_timer_;
    udp::socket reply_socket_;
    udp::endpoint client_;
    udp::endpoint destination_;
    app::config configuration_;
    std::string session_id_;
    bool stopping_{false};
};

boost::asio::awaitable<void> run_socks_association(tcp::socket& control_socket,
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
        co_await socks5::send_reply(control_socket, socks5::reply::kGeneralFailure, ignored);
        co_return;
    }
    relay_socket.bind(udp::endpoint(boost::asio::ip::address_v4::loopback(), 0), ec);
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
        .cleanup_timer = boost::asio::steady_timer(executor),
    });
    boost::asio::co_spawn(executor, run_udp_flow_cleanup(state, close_socks_flow), boost::asio::detached);

    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT
    boost::system::error_code control_ec;
    boost::system::error_code relay_ec;
    co_await (wait_for_control_close(control_socket, control_ec) ||
              run_socks_udp_relay(state, configuration, request, udp::endpoint(tcp_peer.address(), tcp_peer.port()), session_id, relay_ec));

    shutdown_socks_state(state);
    boost::system::error_code ignored;
    control_socket.close(ignored);

    if (relay_ec && relay_ec != boost::asio::error::operation_aborted)
    {
        spdlog::warn("{} socks5 udp association failed: {}", session_id, relay_ec.message());
        co_return;
    }
    if (control_ec && control_ec != boost::asio::error::operation_aborted)
    {
        spdlog::warn("{} socks5 udp control failed: {}", session_id, control_ec.message());
        co_return;
    }
    spdlog::info("{} socks5 udp association completed", session_id);
}

udp::socket create_tproxy_socket(boost::asio::any_io_executor executor,
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

    socket.set_option(boost::asio::socket_base::reuse_address(true), ec);
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

udp_tproxy::udp_tproxy(udp::socket socket, app::config configuration, std::string service_id)
    : socket_(std::move(socket)), configuration_(std::move(configuration)), service_id_(std::move(service_id))
{
}

void udp_tproxy::startup() { boost::asio::co_spawn(socket_.get_executor(), receive_datagrams(), boost::asio::detached); }

boost::asio::awaitable<void> udp_tproxy::receive_datagrams()
{
    boost::system::error_code ec;
    const auto endpoint = socket_.local_endpoint(ec);
    if (ec)
    {
        spdlog::error("{} stopped with error: {}", service_id_, ec.message());
        static_cast<boost::asio::io_context&>(socket_.get_executor().context()).stop();
        co_return;
    }

    spdlog::info("tproxy udp proxy listening on 0.0.0.0:{} ({})", endpoint.port(), service_id_);

    std::array<std::uint8_t, kMaxUdpPacketSize> buffer{};
    for (;;)
    {
        ec.clear();
        co_await socket_.async_wait(udp::socket::wait_read, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            spdlog::error("{} stopped with error: {}", service_id_, ec.message());
            static_cast<boost::asio::io_context&>(socket_.get_executor().context()).stop();
            co_return;
        }

        udp::endpoint client;
        udp::endpoint destination;
        const auto count = transparent::receive_ipv4_original_datagram(socket_, buffer, client, destination, ec);
        // 这些错误表示单个数据报不可用，内核已消费该数据报，跳过即可。
        if (ec == boost::system::errc::message_size || ec == boost::system::errc::no_message_available ||
            ec == boost::system::errc::address_family_not_supported)
        {
            spdlog::warn("{} dropped datagram: {}", service_id_, ec.message());
            continue;
        }
        if (ec)
        {
            spdlog::error("{} stopped with error: {}", service_id_, ec.message());
            static_cast<boost::asio::io_context&>(socket_.get_executor().context()).stop();
            co_return;
        }
        if (!count || *count == 0)
        {
            continue;
        }
        auto session = get_session(client, destination, ec);
        if (ec || !session)
        {
            ec.clear();
            continue;
        }

        auto payload = std::vector<std::uint8_t>(buffer.begin(), buffer.begin() + static_cast<std::ptrdiff_t>(*count));
        static_cast<void>(session->send(std::move(payload)));
    }
}

std::shared_ptr<udp_tproxy_session> udp_tproxy::get_session(const udp::endpoint& client,
                                                            const udp::endpoint& destination,
                                                            boost::system::error_code& ec)
{
    const auto key = tproxy_flow_key(client, destination);
    if (const auto iterator = sessions_.find(key); iterator != sessions_.end())
    {
        if (auto session = iterator->second.lock(); session && !session->stopped())
        {
            return session;
        }
        sessions_.erase(iterator);
    }

    for (auto iterator = sessions_.begin(); iterator != sessions_.end();)
    {
        if (iterator->second.expired())
        {
            iterator = sessions_.erase(iterator);
        }
        else
        {
            ++iterator;
        }
    }

    const auto session_id = service_id_ + "_" + std::to_string(next_session_number_++);
    auto reply_socket = create_transparent_reply_socket(socket_.get_executor(), destination, ec);
    if (ec)
    {
        spdlog::warn(
            "{} tproxy udp reply socket failed for {} -> {}: {}", session_id, format_endpoint(client), format_endpoint(destination), ec.message());
        return nullptr;
    }

    auto session = std::make_shared<udp_tproxy_session>(std::move(reply_socket), client, destination, configuration_, session_id);
    sessions_.emplace(key, session);
    session->startup();
    return session;
}

}    // namespace rv::udp_proxy

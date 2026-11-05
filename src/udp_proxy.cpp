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
constexpr auto kUdpFlowIdleTimeout = std::chrono::seconds(120);

using udp_payload_channel = boost::asio::experimental::channel<void(boost::system::error_code, std::vector<std::uint8_t>)>;

proxy::target make_proxy_target(const udp::endpoint& destination)
{
    return {
        .destination = net::ipv4_address{destination.address().to_v4().to_bytes()},
        .port = destination.port(),
    };
}

std::string format_endpoint(const udp::endpoint& endpoint) { return endpoint.address().to_string() + ":" + std::to_string(endpoint.port()); }

struct socks_uplink_datagram
{
    xudp::endpoint destination;
    std::vector<std::uint8_t> payload;
};

using socks_uplink_channel = boost::asio::experimental::channel<void(boost::system::error_code, socks_uplink_datagram)>;

// 一条 XUDP 连接承载整个 association 发往所有目标的数据报；空闲后关闭，下一个数据报重新建立。
struct socks_udp_upstream
{
    socks_uplink_channel uplink;
    std::optional<xudp::xudp_stream> stream;
    std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};
    std::string session_id;
    bool closed{false};
};

struct socks_udp_state
{
    udp::socket relay_socket;
    std::optional<udp::endpoint> client_endpoint{};
    std::shared_ptr<socks_udp_upstream> upstream;
    std::uint64_t next_upstream_number{1};
    bool closed{false};
};

void close_socks_upstream(socks_udp_upstream& upstream)
{
    if (upstream.closed)
    {
        return;
    }

    upstream.closed = true;
    upstream.uplink.close();
    if (upstream.stream)
    {
        upstream.stream->shutdown();
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
    if (state->upstream)
    {
        close_socks_upstream(*state->upstream);
        state->upstream.reset();
    }
}

boost::asio::awaitable<void> run_socks_downlink(std::shared_ptr<socks_udp_state> state, std::shared_ptr<socks_udp_upstream> upstream)
{
    for (;;)
    {
        boost::system::error_code ec;
        auto response = co_await upstream->stream->read_datagram(ec);
        if (ec)
        {
            if (ec != boost::asio::error::operation_aborted && ec != boost::asio::error::eof)
            {
                spdlog::warn("{} socks5 udp downlink read failed: {}", upstream->session_id, ec.message());
            }
            close_socks_upstream(*upstream);
            co_return;
        }
        if (state->closed || upstream->closed)
        {
            co_return;
        }

        upstream->last_activity = std::chrono::steady_clock::now();
        // 回包头使用服务端给出的真实来源地址（full-cone），与 Xray SOCKS 入站一致。
        auto packet = socks5::encode_udp_datagram(response.source.address, response.source.port, response.payload, ec);
        if (ec)
        {
            spdlog::warn("{} socks5 udp response encode failed: {}", upstream->session_id, ec.message());
            continue;
        }

        co_await state->relay_socket.async_send_to(
            boost::asio::buffer(packet), *state->client_endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            if (ec != boost::asio::error::operation_aborted)
            {
                spdlog::warn("{} socks5 udp downlink send failed: {}", upstream->session_id, ec.message());
            }
            close_socks_upstream(*upstream);
            co_return;
        }
    }
}

boost::asio::awaitable<void> send_socks_uplink(socks_udp_upstream& upstream, boost::system::error_code& ec)
{
    for (;;)
    {
        auto datagram = co_await upstream.uplink.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec || upstream.closed)
        {
            co_return;
        }

        upstream.last_activity = std::chrono::steady_clock::now();
        co_await upstream.stream->write_datagram(datagram.destination, datagram.payload, ec);
        if (ec)
        {
            spdlog::warn("{} socks5 udp uplink failed: {}", upstream.session_id, ec.message());
            co_return;
        }
    }
}

boost::asio::awaitable<void> run_socks_upstream(std::shared_ptr<socks_udp_state> state,
                                                std::shared_ptr<socks_udp_upstream> upstream,
                                                app::config configuration)
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    boost::system::error_code ec;
    const auto id = xudp::make_global_id(format_endpoint(*state->client_endpoint));
    auto stream = co_await proxy::connect_xudp(configuration, id, upstream->session_id, ec);
    if (ec)
    {
        spdlog::warn("{} socks5 udp upstream connection failed: {}", upstream->session_id, ec.message());
    }
    else if (!state->closed && !upstream->closed)
    {
        upstream->stream.emplace(std::move(*stream));
        const auto executor = co_await boost::asio::this_coro::executor;
        boost::asio::co_spawn(executor, run_socks_downlink(state, upstream), boost::asio::detached);
        co_await (send_socks_uplink(*upstream, ec) || proxy::wait_until_idle(upstream->last_activity, kUdpFlowIdleTimeout));
    }
    else
    {
        stream->shutdown();
    }

    close_socks_upstream(*upstream);
    if (state->upstream == upstream)
    {
        state->upstream.reset();
    }
}

std::shared_ptr<socks_udp_upstream> get_socks_upstream(const std::shared_ptr<socks_udp_state>& state,
                                                       const app::config& configuration,
                                                       const std::string& association_id)
{
    if (state->upstream && !state->upstream->closed)
    {
        return state->upstream;
    }

    const auto executor = state->relay_socket.get_executor();
    auto upstream = std::make_shared<socks_udp_upstream>(socks_udp_upstream{
        .uplink = socks_uplink_channel(executor, kUdpFlowQueueCapacity),
        .stream = std::nullopt,
        .session_id = association_id + "_xudp_" + std::to_string(state->next_upstream_number++),
    });
    state->upstream = upstream;
    boost::asio::co_spawn(executor, run_socks_upstream(state, upstream, configuration), boost::asio::detached);
    return upstream;
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
        if (datagram.payload.size() > xudp::kMaximumPayloadSize)
        {
            continue;
        }
        auto upstream = get_socks_upstream(state, configuration, session_id);
        socks_uplink_datagram uplink{
            .destination = {.address = datagram.destination, .port = datagram.port},
            .payload = std::vector<std::uint8_t>(datagram.payload.begin(), datagram.payload.end()),
        };
        if (upstream->uplink.try_send(boost::system::error_code{}, std::move(uplink)))
        {
            upstream->last_activity = std::chrono::steady_clock::now();
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
    auto state = std::make_shared<socks_udp_state>(socks_udp_state{
        .relay_socket = std::move(relay_socket),
    });

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

#include <cstdint>
#include <span>
#include <utility>

#include <spdlog/spdlog.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "tun_udp_session.hpp"

namespace rv::tun
{
namespace
{

constexpr std::size_t kMaximumDatagramPayloadSize = 8190;
constexpr std::size_t kFlowQueueCapacity = 16;
// 与 SOCKS5 UDP association 的上限一致：每个目的地址各占一条 REALITY 连接。
constexpr std::size_t kMaximumFlowsPerClient = 256;
constexpr auto kIdleTimeout = std::chrono::seconds(120);
constexpr auto kIdleCheckInterval = std::chrono::seconds(30);

proxy::target make_proxy_target(const boost::asio::ip::udp::endpoint& endpoint)
{
    if (endpoint.address().is_v4())
    {
        return {.destination = net::ipv4_address{endpoint.address().to_v4().to_bytes()}, .port = endpoint.port()};
    }
    return {.destination = net::ipv6_address{endpoint.address().to_v6().to_bytes()}, .port = endpoint.port()};
}

}    // namespace

tun_udp_session::flow::flow(boost::asio::any_io_executor executor, boost::asio::ip::udp::endpoint target_endpoint, std::string flow_id)
    : target(std::move(target_endpoint)), id(std::move(flow_id)), packets(std::move(executor), kFlowQueueCapacity)
{
}

tun_udp_session::tun_udp_session(boost::asio::any_io_executor executor,
                                 const app::config& configuration,
                                 udp_pcb* pcb,
                                 std::string session_id,
                                 std::function<void()> on_close)
    : executor_(executor),
      configuration_(configuration),
      pcb_(pcb),
      client_(lwip_to_udp_endpoint(pcb->remote_ip, pcb->remote_port)),
      session_id_(std::move(session_id)),
      on_close_(std::move(on_close)),
      idle_timer_(executor)
{
    udp_recv(pcb_, &tun_udp_session::on_recv, this);
}

boost::asio::awaitable<void> tun_udp_session::start()
{
    co_await idle_watchdog();
    close();
    if (on_close_)
    {
        auto on_close = std::move(on_close_);
        on_close();
    }
}

void tun_udp_session::stop() { close(); }

boost::asio::awaitable<void> tun_udp_session::run_flow(std::shared_ptr<flow> current)
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    const auto self = shared_from_this();
    boost::system::error_code ec;
    auto upstream = co_await proxy::connect_udp(configuration_, make_proxy_target(current->target), current->id, ec);
    if (ec || !upstream || current->closed)
    {
        if (upstream)
        {
            upstream->shutdown();
        }
        close_flow(*current);
        co_return;
    }
    current->upstream.emplace(std::move(*upstream));

    boost::system::error_code uplink_ec;
    boost::system::error_code downlink_ec;
    co_await (packets_to_upstream(*current, uplink_ec) || upstream_to_client(*current, downlink_ec));
    if (uplink_ec && uplink_ec != boost::asio::error::operation_aborted)
    {
        spdlog::debug("{} TUN UDP uplink stopped: {}", current->id, uplink_ec.message());
    }
    if (downlink_ec && downlink_ec != boost::asio::error::operation_aborted)
    {
        spdlog::debug("{} TUN UDP downlink stopped: {}", current->id, downlink_ec.message());
    }
    close_flow(*current);
}

boost::asio::awaitable<void> tun_udp_session::packets_to_upstream(flow& current, boost::system::error_code& ec)
{
    for (;;)
    {
        auto payload = co_await current.packets.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec || current.closed)
        {
            co_return;
        }

        co_await current.upstream->write_datagram(payload, ec);
        if (ec)
        {
            co_return;
        }
        current.last_activity = std::chrono::steady_clock::now();
    }
}

boost::asio::awaitable<void> tun_udp_session::upstream_to_client(flow& current, boost::system::error_code& ec)
{
    ip_addr_t source{};
    if (!address_to_lwip(current.target.address(), source))
    {
        co_return;
    }

    for (;;)
    {
        auto payload = co_await current.upstream->read_datagram(ec);
        if (ec || current.closed)
        {
            co_return;
        }
        if (payload.empty() || pcb_ == nullptr)
        {
            continue;
        }
        current.last_activity = std::chrono::steady_clock::now();

        auto* packet = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload.size()), PBUF_RAM);
        if (packet == nullptr)
        {
            continue;
        }
        if (pbuf_take(packet, payload.data(), static_cast<u16_t>(payload.size())) != ERR_OK)
        {
            pbuf_free(packet);
            continue;
        }

        // 回包源地址必须是该 flow 的目的地址，客户端据此区分不同目标的响应。
        const auto send_error = udp_sendfrom(pcb_, packet, &source, current.target.port());
        pbuf_free(packet);
        if (send_error != ERR_OK)
        {
            spdlog::debug("{} TUN UDP send to client failed: {}", current.id, static_cast<int>(send_error));
        }
    }
}

boost::asio::awaitable<void> tun_udp_session::idle_watchdog()
{
    const auto self = shared_from_this();
    while (!stopped_)
    {
        idle_timer_.expires_after(kIdleCheckInterval);
        boost::system::error_code ec;
        co_await idle_timer_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec || stopped_)
        {
            co_return;
        }

        const auto now = std::chrono::steady_clock::now();
        for (auto iterator = flows_.begin(); iterator != flows_.end();)
        {
            auto current = iterator++;
            if (now - current->second->last_activity >= kIdleTimeout)
            {
                close_flow(*current->second);
            }
        }
        if (flows_.empty())
        {
            co_return;
        }
    }
}

void tun_udp_session::enqueue_packet(pbuf* packet, const boost::asio::ip::udp::endpoint& target)
{
    auto payload = pbuf_to_vector(packet);
    pbuf_free(packet);
    if (stopped_ || payload.empty() || payload.size() > kMaximumDatagramPayloadSize || target.port() == 0 || client_.port() == 0)
    {
        return;
    }

    auto iterator = flows_.find(target);
    if (iterator == flows_.end())
    {
        if (flows_.size() >= kMaximumFlowsPerClient)
        {
            spdlog::warn("{} TUN UDP flow limit reached, dropping datagram to {}", session_id_, target.address().to_string());
            return;
        }
        auto current = std::make_shared<flow>(executor_, target, session_id_ + "_" + std::to_string(next_flow_number_++));
        iterator = flows_.emplace(target, current).first;
        spdlog::info("{} TUN UDP flow {} -> {}:{}", current->id, client_.address().to_string(), target.address().to_string(), target.port());
        boost::asio::co_spawn(executor_, run_flow(std::move(current)), boost::asio::detached);
    }

    auto& current = *iterator->second;
    current.last_activity = std::chrono::steady_clock::now();
    static_cast<void>(current.packets.try_send(boost::system::error_code{}, std::move(payload)));
}

void tun_udp_session::close_flow(flow& current)
{
    if (current.closed)
    {
        return;
    }
    current.closed = true;
    current.packets.close();
    if (current.upstream)
    {
        current.upstream->shutdown();
    }
    // run_flow 协程持有 flow 的 shared_ptr，erase 不会销毁正在使用的对象。
    if (const auto iterator = flows_.find(current.target); iterator != flows_.end() && iterator->second.get() == &current)
    {
        flows_.erase(iterator);
    }
    if (flows_.empty())
    {
        static_cast<void>(idle_timer_.cancel());
    }
}

void tun_udp_session::close()
{
    if (stopped_)
    {
        return;
    }
    stopped_ = true;
    static_cast<void>(idle_timer_.cancel());

    auto flows = std::move(flows_);
    flows_.clear();
    for (auto& [target, current] : flows)
    {
        static_cast<void>(target);
        close_flow(*current);
    }
    if (pcb_ != nullptr)
    {
        auto* pcb = pcb_;
        pcb_ = nullptr;
        udp_recv(pcb, nullptr, nullptr);
        udp_remove(pcb);
    }
}

void tun_udp_session::on_recv(void* argument, udp_pcb* pcb, pbuf* packet, const ip_addr_t* address, const u16_t port)
{
    static_cast<void>(address);
    static_cast<void>(port);
    if (packet == nullptr)
    {
        return;
    }
    auto* self = static_cast<tun_udp_session*>(argument);
    if (self == nullptr)
    {
        pbuf_free(packet);
        return;
    }
    // heiher lwIP 在回调前把 pretend pcb 的 local 地址改写为本包的目的地址。
    self->enqueue_packet(packet, lwip_to_udp_endpoint(pcb->local_ip, pcb->local_port));
}

}    // namespace rv::tun

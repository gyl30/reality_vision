#include <cstdint>
#include <span>
#include <utility>
#include <variant>

#include <spdlog/spdlog.h>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "tun_udp_session.hpp"

namespace rv::tun
{
namespace
{

constexpr std::size_t kPacketQueueCapacity = 16;
constexpr auto kIdleTimeout = std::chrono::seconds(120);

xudp::endpoint to_xudp_endpoint(const boost::asio::ip::udp::endpoint& endpoint)
{
    if (endpoint.address().is_v4())
    {
        return {.address = net::ipv4_address{endpoint.address().to_v4().to_bytes()}, .port = endpoint.port()};
    }
    return {.address = net::ipv6_address{endpoint.address().to_v6().to_bytes()}, .port = endpoint.port()};
}

// TUN 目的地址总是 IP，Xray 对 IP 目标回报 IP 来源；域名来源无法作为 IP 包源地址，返回 false。
bool to_lwip_source(const xudp::endpoint& endpoint, ip_addr_t& output)
{
    if (const auto* address = std::get_if<net::ipv4_address>(&endpoint.address))
    {
        return address_to_lwip(boost::asio::ip::address_v4(address->bytes), output);
    }
    if (const auto* address = std::get_if<net::ipv6_address>(&endpoint.address))
    {
        return address_to_lwip(boost::asio::ip::address_v6(address->bytes), output);
    }
    return false;
}

}    // namespace

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
      packets_(executor, kPacketQueueCapacity)
{
    udp_recv(pcb_, &tun_udp_session::on_recv, this);
}

boost::asio::awaitable<void> tun_udp_session::start()
{
    const auto self = shared_from_this();
    co_await run();
    close();
    if (on_close_)
    {
        auto on_close = std::move(on_close_);
        on_close();
    }
}

void tun_udp_session::stop() { close(); }

boost::asio::awaitable<void> tun_udp_session::run()
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    boost::system::error_code ec;
    auto upstream = co_await proxy::connect_xudp(configuration_, xudp::make_global_id(client_.address().to_string() + ":" + std::to_string(client_.port())), session_id_, ec);
    if (ec || stopped_)
    {
        if (upstream)
        {
            upstream->shutdown();
        }
        co_return;
    }
    upstream_.emplace(std::move(*upstream));

    boost::system::error_code uplink_ec;
    boost::system::error_code downlink_ec;
    co_await (packets_to_upstream(uplink_ec) || upstream_to_client(downlink_ec) || proxy::wait_until_idle(last_activity_, kIdleTimeout));
    if (uplink_ec && uplink_ec != boost::asio::error::operation_aborted)
    {
        spdlog::debug("{} TUN UDP uplink stopped: {}", session_id_, uplink_ec.message());
    }
    if (downlink_ec && downlink_ec != boost::asio::error::operation_aborted && downlink_ec != boost::asio::error::eof)
    {
        spdlog::debug("{} TUN UDP downlink stopped: {}", session_id_, downlink_ec.message());
    }
}

boost::asio::awaitable<void> tun_udp_session::packets_to_upstream(boost::system::error_code& ec)
{
    for (;;)
    {
        auto datagram = co_await packets_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec || stopped_)
        {
            co_return;
        }

        co_await upstream_->write_datagram(datagram.destination, datagram.payload, ec);
        if (ec)
        {
            co_return;
        }
        last_activity_ = std::chrono::steady_clock::now();
    }
}

boost::asio::awaitable<void> tun_udp_session::upstream_to_client(boost::system::error_code& ec)
{
    for (;;)
    {
        auto response = co_await upstream_->read_datagram(ec);
        if (ec || stopped_)
        {
            co_return;
        }
        ip_addr_t source{};
        if (pcb_ == nullptr || !to_lwip_source(response.source, source))
        {
            continue;
        }
        last_activity_ = std::chrono::steady_clock::now();

        auto* packet = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(response.payload.size()), PBUF_RAM);
        if (packet == nullptr)
        {
            continue;
        }
        if (pbuf_take(packet, response.payload.data(), static_cast<u16_t>(response.payload.size())) != ERR_OK)
        {
            pbuf_free(packet);
            continue;
        }

        // 回包源地址使用服务端给出的来源地址，客户端据此区分不同目标的响应。
        const auto send_error = udp_sendfrom(pcb_, packet, &source, response.source.port);
        pbuf_free(packet);
        if (send_error != ERR_OK)
        {
            spdlog::debug("{} TUN UDP send to client failed: {}", session_id_, static_cast<int>(send_error));
        }
    }
}

void tun_udp_session::enqueue_packet(pbuf* packet, const boost::asio::ip::udp::endpoint& target)
{
    auto payload = pbuf_to_vector(packet);
    pbuf_free(packet);
    if (stopped_ || payload.empty() || payload.size() > xudp::kMaximumPayloadSize || target.port() == 0 || client_.port() == 0)
    {
        return;
    }

    if (packets_.try_send(boost::system::error_code{}, uplink_datagram{.destination = to_xudp_endpoint(target), .payload = std::move(payload)}))
    {
        last_activity_ = std::chrono::steady_clock::now();
    }
}

void tun_udp_session::close()
{
    if (stopped_)
    {
        return;
    }
    stopped_ = true;
    packets_.close();
    if (upstream_)
    {
        upstream_->shutdown();
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

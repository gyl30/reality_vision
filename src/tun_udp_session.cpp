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
constexpr auto kIdleTimeout = std::chrono::seconds(120);

proxy::target make_proxy_target(const boost::asio::ip::udp::endpoint& endpoint)
{
    if (endpoint.address().is_v4())
    {
        return {.destination = net::ipv4_address{endpoint.address().to_v4().to_bytes()}, .port = endpoint.port()};
    }
    return {.destination = net::ipv6_address{endpoint.address().to_v6().to_bytes()}, .port = endpoint.port()};
}

}    // namespace

tun_udp_session::tun_udp_session(boost::asio::any_io_executor executor,
                                 const app::config& configuration,
                                 udp_pcb* pcb,
                                 boost::asio::ip::udp::endpoint client,
                                 boost::asio::ip::udp::endpoint target,
                                 const std::uint32_t id,
                                 std::string session_id,
                                 std::function<void()> on_close)
    : configuration_(configuration),
      pcb_(pcb),
      client_(std::move(client)),
      target_endpoint_(std::move(target)),
      target_(make_proxy_target(target_endpoint_)),
      id_(id),
      session_id_(std::move(session_id)),
      on_close_(std::move(on_close)),
      packets_(executor, 16),
      idle_timer_(executor)
{
    udp_recv(pcb_, &tun_udp_session::on_recv, this);
}

boost::asio::awaitable<void> tun_udp_session::start()
{
    co_await run();
    close();
    notify_closed();
}

void tun_udp_session::stop() { close(); }

boost::asio::awaitable<void> tun_udp_session::run()
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    boost::system::error_code ec;
    upstream_ = co_await proxy::connect_udp(configuration_, target_, session_id_, ec);
    if (ec || !upstream_ || stopped_.load(std::memory_order_relaxed))
    {
        if (upstream_)
        {
            upstream_->shutdown();
        }
        co_return;
    }

    const auto self = shared_from_this();
    boost::asio::co_spawn(
        idle_timer_.get_executor(),
        [self]() -> boost::asio::awaitable<void> { co_await self->idle_watchdog(); },
        boost::asio::detached);

    boost::system::error_code uplink_ec;
    boost::system::error_code downlink_ec;
    co_await (packets_to_upstream(*upstream_, uplink_ec) && upstream_to_client(*upstream_, downlink_ec));
    if (uplink_ec && uplink_ec != boost::asio::error::operation_aborted)
    {
        spdlog::debug("{} TUN UDP uplink stopped: {}", session_id_, uplink_ec.message());
    }
    if (downlink_ec && downlink_ec != boost::asio::error::operation_aborted)
    {
        spdlog::debug("{} TUN UDP downlink stopped: {}", session_id_, downlink_ec.message());
    }
}

boost::asio::awaitable<void> tun_udp_session::packets_to_upstream(vless::vless_udp_stream& upstream,
                                                                  boost::system::error_code& ec)
{
    for (;;)
    {
        auto payload = co_await packets_.async_receive(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec || stopped_.load(std::memory_order_relaxed))
        {
            co_return;
        }

        co_await upstream.write_datagram(payload, ec);
        if (ec)
        {
            co_return;
        }
        last_activity_ = std::chrono::steady_clock::now();
    }
}

boost::asio::awaitable<void> tun_udp_session::upstream_to_client(vless::vless_udp_stream& upstream,
                                                                  boost::system::error_code& ec)
{
    for (;;)
    {
        auto payload = co_await upstream.read_datagram(ec);
        if (ec || stopped_.load(std::memory_order_relaxed))
        {
            co_return;
        }
        if (payload.empty() || pcb_ == nullptr)
        {
            continue;
        }
        last_activity_ = std::chrono::steady_clock::now();

        ip_addr_t source{};
        if (!address_to_lwip(target_endpoint_.address(), source))
        {
            co_return;
        }

        auto* packet = pbuf_alloc(PBUF_TRANSPORT, static_cast<u16_t>(payload.size()), PBUF_RAM);
        if (packet == nullptr)
        {
            co_return;
        }
        if (pbuf_take(packet, payload.data(), static_cast<u16_t>(payload.size())) != ERR_OK)
        {
            pbuf_free(packet);
            co_return;
        }

        const auto send_error = udp_sendfrom(pcb_, packet, &source, target_endpoint_.port());
        pbuf_free(packet);
        if (send_error != ERR_OK)
        {
            co_return;
        }
    }
}

boost::asio::awaitable<void> tun_udp_session::idle_watchdog()
{
    while (!stopped_.load(std::memory_order_relaxed))
    {
        idle_timer_.expires_after(std::chrono::seconds(30));
        boost::system::error_code ec;
        co_await idle_timer_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec || stopped_.load(std::memory_order_relaxed))
        {
            co_return;
        }
        if (std::chrono::steady_clock::now() - last_activity_ >= kIdleTimeout)
        {
            close();
            co_return;
        }
    }
}

void tun_udp_session::enqueue_packet(pbuf* packet)
{
    if (packet == nullptr)
    {
        return;
    }

    auto payload = pbuf_to_vector(packet);
    pbuf_free(packet);
    if (stopped_.load(std::memory_order_relaxed) || payload.empty() || payload.size() > kMaximumDatagramPayloadSize)
    {
        return;
    }
    last_activity_ = std::chrono::steady_clock::now();
    static_cast<void>(packets_.try_send(boost::system::error_code{}, std::move(payload)));
}

void tun_udp_session::close()
{
    if (stopped_.exchange(true, std::memory_order_relaxed))
    {
        return;
    }

    packets_.close();
    static_cast<void>(idle_timer_.cancel());
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

void tun_udp_session::notify_closed()
{
    if (on_close_)
    {
        auto on_close = std::move(on_close_);
        on_close();
    }
}

void tun_udp_session::on_recv(void* argument, udp_pcb* pcb, pbuf* packet, const ip_addr_t* address, const u16_t port)
{
    static_cast<void>(pcb);
    static_cast<void>(address);
    static_cast<void>(port);
    if (auto* self = static_cast<tun_udp_session*>(argument); self != nullptr)
    {
        self->enqueue_packet(packet);
    }
    else if (packet != nullptr)
    {
        pbuf_free(packet);
    }
}

}    // namespace rv::tun

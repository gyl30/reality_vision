#include <algorithm>
#include <array>
#include <limits>
#include <span>
#include <utility>

#include <spdlog/spdlog.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "proxy_common.hpp"
#include "tun_tcp_session.hpp"

namespace rv::tun
{
namespace
{

constexpr std::size_t kRelayBufferSize = 16UL * 1024U;

proxy::target make_proxy_target(const ip_addr_t& address, const std::uint16_t port)
{
    const auto value = lwip_to_address(address);
    if (value.is_v4())
    {
        return {.destination = net::ipv4_address{value.to_v4().to_bytes()}, .port = port};
    }
    return {.destination = net::ipv6_address{value.to_v6().to_bytes()}, .port = port};
}

void acknowledge_tcp_bytes(tcp_pcb* pcb, std::size_t size)
{
    while (pcb != nullptr && size != 0)
    {
        const auto chunk = static_cast<u16_t>(std::min<std::size_t>(size, std::numeric_limits<u16_t>::max()));
        tcp_recved(pcb, chunk);
        size -= chunk;
    }
}

}    // namespace

tun_tcp_session::tun_tcp_session(boost::asio::any_io_executor executor,
                                 const app::config& configuration,
                                 tcp_pcb* pcb,
                                 const std::uint32_t id,
                                 std::string session_id,
                                 std::function<void()> on_close)
    : configuration_(configuration),
      pcb_(pcb),
      id_(id),
      session_id_(std::move(session_id)),
      target_(make_proxy_target(pcb->local_ip, pcb->local_port)),
      on_close_(std::move(on_close)),
      client_wait_timer_(executor),
      send_wait_timer_(executor)
{
    tcp_arg(pcb_, this);
    tcp_recv(pcb_, &tun_tcp_session::on_recv);
    tcp_sent(pcb_, &tun_tcp_session::on_sent);
    tcp_err(pcb_, &tun_tcp_session::on_err);
    tcp_poll(pcb_, &tun_tcp_session::on_poll, 2);
    tcp_nagle_disable(pcb_);
}

boost::asio::awaitable<void> tun_tcp_session::start()
{
    // 只有双向正常结束才发 FIN；上游连接失败或中继出错时发 RST，与真实 TCP 连接的失败语义一致。
    const bool completed = co_await run();
    close_client(!completed);
    notify_closed();
}

void tun_tcp_session::stop() { close_client(true); }

boost::asio::awaitable<bool> tun_tcp_session::run()
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    boost::system::error_code ec;
    auto reality = co_await proxy::connect_reality(configuration_, session_id_, ec);
    if (ec || !reality || stopped_.load(std::memory_order_relaxed))
    {
        co_return false;
    }

    upstream_ = co_await proxy::connect_vision(std::move(*reality), configuration_, target_, session_id_, ec);
    if (ec || !upstream_ || stopped_.load(std::memory_order_relaxed))
    {
        co_return false;
    }

    boost::system::error_code client_ec;
    boost::system::error_code upstream_ec;
    co_await (client_to_upstream(*upstream_, client_ec) && upstream_to_client(*upstream_, upstream_ec));
    if (client_ec && client_ec != boost::asio::error::operation_aborted)
    {
        spdlog::debug("{} TUN TCP client relay stopped: {}", session_id_, client_ec.message());
    }
    if (upstream_ec && upstream_ec != boost::asio::error::operation_aborted)
    {
        spdlog::debug("{} TUN TCP upstream relay stopped: {}", session_id_, upstream_ec.message());
    }
    co_return !client_ec && !upstream_ec;
}

boost::asio::awaitable<void> tun_tcp_session::client_to_upstream(vision::vision_stream& upstream,
                                                                 boost::system::error_code& ec)
{
    for (;;)
    {
        while (pending_ == nullptr && !peer_eof_ && !stopped_.load(std::memory_order_relaxed))
        {
            co_await wait_client_event();
        }

        if (stopped_.load(std::memory_order_relaxed))
        {
            co_return;
        }

        if (pending_ != nullptr)
        {
            auto* packet = pending_;
            pending_ = nullptr;
            const auto payload = pbuf_to_vector(packet);
            const auto size = payload.size();
            pbuf_free(packet);
            if (!payload.empty())
            {
                co_await upstream.write(payload, ec);
                if (ec)
                {
                    stopped_.store(true, std::memory_order_relaxed);
                    signal_all_events();
                    upstream.shutdown();
                    co_return;
                }
                acknowledge_tcp_bytes(pcb_, size);
            }
        }

        if (peer_eof_ && pending_ == nullptr)
        {
            co_await upstream.shutdown_send(ec);
            if (ec)
            {
                stopped_.store(true, std::memory_order_relaxed);
                signal_all_events();
                upstream.shutdown();
            }
            co_return;
        }
    }
}

boost::asio::awaitable<void> tun_tcp_session::upstream_to_client(vision::vision_stream& upstream,
                                                                 boost::system::error_code& ec)
{
    std::array<std::uint8_t, kRelayBufferSize> buffer{};
    for (;;)
    {
        const auto count = co_await upstream.read(buffer, ec);
        if (ec)
        {
            stopped_.store(true, std::memory_order_relaxed);
            signal_all_events();
            co_return;
        }
        if (count == 0)
        {
            if (pcb_ != nullptr)
            {
                static_cast<void>(tcp_shutdown(pcb_, 0, 1));
            }
            co_return;
        }

        std::size_t offset = 0;
        while (offset < count && pcb_ != nullptr && !stopped_.load(std::memory_order_relaxed))
        {
            const auto available = static_cast<std::size_t>(tcp_sndbuf(pcb_));
            if (available == 0)
            {
                co_await wait_send_event();
                continue;
            }

            const auto chunk = std::min({available, count - offset, static_cast<std::size_t>(std::numeric_limits<u16_t>::max())});
            const auto write_error = tcp_write(pcb_, buffer.data() + offset, static_cast<u16_t>(chunk), TCP_WRITE_FLAG_COPY);
            if (write_error == ERR_MEM)
            {
                co_await wait_send_event();
                continue;
            }
            if (write_error != ERR_OK)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
                stopped_.store(true, std::memory_order_relaxed);
                signal_all_events();
                co_return;
            }

            if (tcp_output(pcb_) != ERR_OK)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
                stopped_.store(true, std::memory_order_relaxed);
                signal_all_events();
                co_return;
            }
            offset += chunk;
        }
    }
}

boost::asio::awaitable<void> tun_tcp_session::wait_client_event()
{
    client_wait_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    boost::system::error_code ec;
    co_await client_wait_timer_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
}

boost::asio::awaitable<void> tun_tcp_session::wait_send_event()
{
    send_wait_timer_.expires_at(std::chrono::steady_clock::time_point::max());
    boost::system::error_code ec;
    co_await send_wait_timer_.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
}

void tun_tcp_session::signal_client_event() { static_cast<void>(client_wait_timer_.cancel()); }

void tun_tcp_session::signal_send_event() { static_cast<void>(send_wait_timer_.cancel()); }

void tun_tcp_session::signal_all_events()
{
    signal_client_event();
    signal_send_event();
}

void tun_tcp_session::close_client(const bool abort_connection)
{
    stopped_.store(true, std::memory_order_relaxed);
    signal_all_events();
    if (pending_ != nullptr)
    {
        pbuf_free(pending_);
        pending_ = nullptr;
    }
    if (upstream_)
    {
        upstream_->shutdown();
    }

    if (pcb_ == nullptr)
    {
        return;
    }

    auto* pcb = pcb_;
    pcb_ = nullptr;
    tcp_arg(pcb, nullptr);
    tcp_recv(pcb, nullptr);
    tcp_sent(pcb, nullptr);
    tcp_err(pcb, nullptr);
    tcp_poll(pcb, nullptr, 0);
    if (abort_connection || tcp_close(pcb) != ERR_OK)
    {
        tcp_abort(pcb);
    }
}

void tun_tcp_session::notify_closed()
{
    if (on_close_)
    {
        auto on_close = std::move(on_close_);
        on_close();
    }
}

err_t tun_tcp_session::on_recv(void* argument, tcp_pcb* pcb, pbuf* packet, const err_t error)
{
    auto* self = static_cast<tun_tcp_session*>(argument);
    if (self == nullptr)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        return ERR_OK;
    }

    if (error != ERR_OK)
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        self->stopped_.store(true, std::memory_order_relaxed);
        self->pcb_ = nullptr;
        self->signal_all_events();
        if (self->upstream_)
        {
            self->upstream_->shutdown();
        }
        tcp_arg(pcb, nullptr);
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    if (packet == nullptr)
    {
        self->peer_eof_ = true;
        self->signal_client_event();
        return ERR_OK;
    }

    if (self->pending_ == nullptr)
    {
        self->pending_ = packet;
    }
    else
    {
        pbuf_cat(self->pending_, packet);
    }
    self->signal_client_event();
    return ERR_OK;
}

err_t tun_tcp_session::on_sent(void* argument, tcp_pcb* pcb, const u16_t length)
{
    static_cast<void>(pcb);
    static_cast<void>(length);
    if (auto* self = static_cast<tun_tcp_session*>(argument); self != nullptr)
    {
        self->signal_send_event();
    }
    return ERR_OK;
}

void tun_tcp_session::on_err(void* argument, const err_t error)
{
    static_cast<void>(error);
    if (auto* self = static_cast<tun_tcp_session*>(argument); self != nullptr)
    {
        self->pcb_ = nullptr;
        self->stopped_.store(true, std::memory_order_relaxed);
        self->signal_all_events();
        if (self->upstream_)
        {
            self->upstream_->shutdown();
        }
    }
}

err_t tun_tcp_session::on_poll(void* argument, tcp_pcb* pcb)
{
    static_cast<void>(pcb);
    if (auto* self = static_cast<tun_tcp_session*>(argument); self != nullptr)
    {
        self->signal_send_event();
        self->signal_client_event();
    }
    return ERR_OK;
}

}    // namespace rv::tun

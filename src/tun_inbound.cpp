#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <unistd.h>

#include <spdlog/spdlog.h>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/system/errc.hpp>

#include "tun_inbound.hpp"
#include "tun_tcp_session.hpp"
#include "tun_udp_session.hpp"

namespace rv::tun
{

tun_inbound::tun_inbound(boost::asio::io_context& context, const app::config& configuration)
    : configuration_(configuration), tun_stream_(context)
{
}

bool tun_inbound::start(boost::system::error_code& ec)
{
    if (!device_.open(configuration_.tun_name, ec))
    {
        return false;
    }

    const int wait_fd = ::dup(device_.native_handle());
    if (wait_fd < 0)
    {
        ec = {errno, boost::system::system_category()};
        device_.close();
        return false;
    }
    tun_stream_.assign(wait_fd, ec);
    if (ec)
    {
        ::close(wait_fd);
        device_.close();
        return false;
    }

    if (!initialize_stack(ec))
    {
        tun_stream_.close();
        device_.close();
        return false;
    }

    stopping_.store(false, std::memory_order_relaxed);
    boost::asio::co_spawn(tun_stream_.get_executor(), read_loop(), boost::asio::detached);
    boost::asio::co_spawn(tun_stream_.get_executor(), timer_loop(), boost::asio::detached);
    spdlog::info("TUN inbound {} started", device_.name());
    return true;
}

void tun_inbound::stop()
{
    if (stopping_.exchange(true, std::memory_order_relaxed))
    {
        return;
    }

    boost::system::error_code ignored;
    tun_stream_.close(ignored);
    shutdown_stack();
    device_.close();
}

bool tun_inbound::initialize_stack(boost::system::error_code& ec)
{
    lwip_init();
    ec.clear();

    if (netif_add_noaddr(&netif_, this, &tun_inbound::netif_init_handler, ip_input) == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
        return false;
    }
    stack_ready_ = true;
    netif_.mtu = configuration_.tun_mtu;

    ip4_addr_t address4;
    ip4_addr_t mask4;
    ip4_addr_t gateway4;
    ip4_addr_set_loopback(&address4);
    ip4_addr_set_any(&mask4);
    ip4_addr_set_any(&gateway4);
    netif_set_addr(&netif_, &address4, &mask4, &gateway4);

    ip6_addr_t address6;
    ip6_addr_set_loopback(&address6);
    static_cast<void>(netif_add_ip6_address(&netif_, &address6, nullptr));

    netif_set_up(&netif_);
    netif_set_link_up(&netif_);
    netif_set_default(&netif_);
    netif_set_flags(&netif_, NETIF_FLAG_PRETEND);

    tcp_listener_ = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (tcp_listener_ == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        shutdown_stack();
        return false;
    }
    tcp_bind_netif(tcp_listener_, &netif_);
    if (tcp_bind(tcp_listener_, nullptr, 0) != ERR_OK)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::address_in_use);
        shutdown_stack();
        return false;
    }
    tcp_listener_ = tcp_listen(tcp_listener_);
    if (tcp_listener_ == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::io_error);
        shutdown_stack();
        return false;
    }
    tcp_arg(tcp_listener_, this);
    tcp_accept(tcp_listener_, &tun_inbound::tcp_accept_handler);

    udp_listener_ = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (udp_listener_ == nullptr)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::not_enough_memory);
        shutdown_stack();
        return false;
    }
    udp_bind_netif(udp_listener_, &netif_);
    if (udp_bind(udp_listener_, nullptr, 0) != ERR_OK)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::address_in_use);
        shutdown_stack();
        return false;
    }
    udp_recv(udp_listener_, &tun_inbound::udp_recv_handler, this);
    return true;
}

void tun_inbound::shutdown_stack()
{
    for (auto& [id, session] : tcp_sessions_)
    {
        static_cast<void>(id);
        session->stop();
    }
    tcp_sessions_.clear();
    for (auto& [id, session] : udp_sessions_)
    {
        static_cast<void>(id);
        session->stop();
    }
    udp_sessions_.clear();

    if (udp_listener_ != nullptr)
    {
        udp_recv(udp_listener_, nullptr, nullptr);
        udp_remove(udp_listener_);
        udp_listener_ = nullptr;
    }
    if (tcp_listener_ != nullptr)
    {
        tcp_accept(tcp_listener_, nullptr);
        tcp_arg(tcp_listener_, nullptr);
        if (tcp_close(tcp_listener_) != ERR_OK)
        {
            tcp_abort(tcp_listener_);
        }
        tcp_listener_ = nullptr;
    }
    if (stack_ready_)
    {
        netif_remove(&netif_);
        stack_ready_ = false;
    }
}

boost::asio::awaitable<void> tun_inbound::read_loop()
{
    std::array<std::uint8_t, 65535> buffer{};
    while (!stopping_.load(std::memory_order_relaxed))
    {
        boost::system::error_code ec;
        co_await tun_stream_.async_wait(boost::asio::posix::descriptor_base::wait_read,
                                        boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec == boost::asio::error::operation_aborted || ec == boost::asio::error::bad_descriptor)
        {
            co_return;
        }
        if (ec)
        {
            spdlog::error("TUN {} read wait failed: {}", device_.name(), ec.message());
            co_return;
        }

        for (;;)
        {
            const auto count = device_.read_packet(buffer.data(), buffer.size(), ec);
            if (ec == boost::asio::error::would_block || ec == boost::asio::error::try_again ||
                ec == boost::system::errc::make_error_code(boost::system::errc::resource_unavailable_try_again))
            {
                break;
            }
            if (ec)
            {
                spdlog::error("TUN {} read failed: {}", device_.name(), ec.message());
                co_return;
            }
            if (count <= 0)
            {
                break;
            }
            process_packet(buffer.data(), static_cast<std::size_t>(count));
        }
    }
}

boost::asio::awaitable<void> tun_inbound::timer_loop()
{
    boost::asio::steady_timer timer(tun_stream_.get_executor());
    std::uint32_t tick = 0;
    while (!stopping_.load(std::memory_order_relaxed))
    {
        timer.expires_after(std::chrono::milliseconds(TCP_TMR_INTERVAL));
        boost::system::error_code ec;
        co_await timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (ec)
        {
            co_return;
        }

        ++tick;
        tcp_tmr();
        if ((tick & 3U) == 0)
        {
#if IP_REASSEMBLY
            ip_reass_tmr();
#endif
#if LWIP_IPV6
            nd6_tmr();
#if LWIP_IPV6_REASS
            ip6_reass_tmr();
#endif
#endif
        }
    }
}

void tun_inbound::process_packet(const std::uint8_t* data, const std::size_t size)
{
    if (size == 0 || size > 65535)
    {
        return;
    }
    auto* packet = pbuf_alloc(PBUF_RAW, static_cast<u16_t>(size), PBUF_RAM);
    if (packet == nullptr)
    {
        return;
    }
    if (pbuf_take(packet, data, static_cast<u16_t>(size)) != ERR_OK)
    {
        pbuf_free(packet);
        return;
    }
    if (netif_.input(packet, &netif_) != ERR_OK)
    {
        pbuf_free(packet);
    }
}

err_t tun_inbound::write_packet(const pbuf* packet)
{
    const auto payload = pbuf_to_vector(packet);
    if (payload.empty())
    {
        return ERR_OK;
    }

    boost::system::error_code ec;
    const auto count = device_.write_packet(payload.data(), payload.size(), ec);
    if (ec == boost::asio::error::would_block || ec == boost::asio::error::try_again ||
        ec == boost::system::errc::make_error_code(boost::system::errc::resource_unavailable_try_again))
    {
        return ERR_WOULDBLOCK;
    }
    if (ec || count != static_cast<std::ptrdiff_t>(payload.size()))
    {
        return ERR_IF;
    }
    return ERR_OK;
}

void tun_inbound::on_tcp_accept(tcp_pcb* pcb)
{
    const auto id = next_session_id_++;
    std::weak_ptr<tun_inbound> weak_self = shared_from_this();
    auto session = std::make_shared<tun_tcp_session>(
        tun_stream_.get_executor(),
        configuration_,
        pcb,
        id,
        "tun_tcp_" + std::to_string(id),
        [weak_self, id]
        {
            if (auto self = weak_self.lock())
            {
                self->erase_tcp_session(id);
            }
        });
    tcp_sessions_.emplace(id, session);
    boost::asio::co_spawn(
        tun_stream_.get_executor(),
        [session = std::move(session)]() -> boost::asio::awaitable<void> { co_await session->start(); },
        boost::asio::detached);
}

void tun_inbound::on_udp_accept(udp_pcb* pcb, const ip_addr_t* address, const std::uint16_t port)
{
    if (pcb == nullptr || address == nullptr || pcb->remote_port == 0 || port == 0)
    {
        return;
    }

    const auto client = lwip_to_udp_endpoint(pcb->remote_ip, pcb->remote_port);
    const auto target = lwip_to_udp_endpoint(*address, port);
    const auto id = next_session_id_++;
    std::weak_ptr<tun_inbound> weak_self = shared_from_this();
    auto session = std::make_shared<tun_udp_session>(
        tun_stream_.get_executor(),
        configuration_,
        pcb,
        client,
        target,
        id,
        "tun_udp_" + std::to_string(id),
        [weak_self, id]
        {
            if (auto self = weak_self.lock())
            {
                self->erase_udp_session(id);
            }
        });
    udp_sessions_.emplace(id, session);
    boost::asio::co_spawn(
        tun_stream_.get_executor(),
        [session = std::move(session)]() -> boost::asio::awaitable<void> { co_await session->start(); },
        boost::asio::detached);
}

void tun_inbound::erase_tcp_session(const std::uint32_t id) { tcp_sessions_.erase(id); }

void tun_inbound::erase_udp_session(const std::uint32_t id) { udp_sessions_.erase(id); }

err_t tun_inbound::netif_init_handler(netif* interface_)
{
    interface_->output = &tun_inbound::netif_output_v4_handler;
    interface_->output_ip6 = &tun_inbound::netif_output_v6_handler;
    return ERR_OK;
}

err_t tun_inbound::netif_output_v4_handler(netif* interface_, pbuf* packet, const ip4_addr_t* address)
{
    static_cast<void>(address);
    if (interface_ == nullptr || interface_->state == nullptr)
    {
        return ERR_IF;
    }
    return static_cast<tun_inbound*>(interface_->state)->write_packet(packet);
}

err_t tun_inbound::netif_output_v6_handler(netif* interface_, pbuf* packet, const ip6_addr_t* address)
{
    static_cast<void>(address);
    if (interface_ == nullptr || interface_->state == nullptr)
    {
        return ERR_IF;
    }
    return static_cast<tun_inbound*>(interface_->state)->write_packet(packet);
}

err_t tun_inbound::tcp_accept_handler(void* argument, tcp_pcb* pcb, const err_t error)
{
    auto* self = static_cast<tun_inbound*>(argument);
    if (self == nullptr || pcb == nullptr || error != ERR_OK || self->stopping_.load(std::memory_order_relaxed))
    {
        return ERR_ABRT;
    }
    self->on_tcp_accept(pcb);
    return ERR_OK;
}

void tun_inbound::udp_recv_handler(void* argument,
                                   udp_pcb* pcb,
                                   pbuf* packet,
                                   const ip_addr_t* address,
                                   const u16_t port)
{
    auto* self = static_cast<tun_inbound*>(argument);
    if (self == nullptr || self->stopping_.load(std::memory_order_relaxed))
    {
        if (packet != nullptr)
        {
            pbuf_free(packet);
        }
        return;
    }
    self->on_udp_accept(pcb, address, port);
}

}    // namespace rv::tun

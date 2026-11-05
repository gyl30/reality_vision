#ifndef REALITY_VISION_TUN_INBOUND_HPP
#define REALITY_VISION_TUN_INBOUND_HPP

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

#include <boost/asio/posix/stream_descriptor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "config.hpp"
#include "tun_device.hpp"
#include "tun_lwip.hpp"

namespace rv::tun
{

class tun_tcp_session;
class tun_udp_session;

class tun_inbound : public std::enable_shared_from_this<tun_inbound>
{
   public:
    tun_inbound(boost::asio::io_context& context, const app::config& configuration);

    [[nodiscard]] bool start(boost::system::error_code& ec);
    void stop();

   private:
    [[nodiscard]] bool initialize_stack(boost::system::error_code& ec);
    void shutdown_stack();
    [[nodiscard]] boost::asio::awaitable<void> read_loop();
    [[nodiscard]] boost::asio::awaitable<void> timer_loop();
    void process_packet(const std::uint8_t* data, std::size_t size);
    [[nodiscard]] err_t write_packet(const pbuf* packet);
    void on_tcp_accept(tcp_pcb* pcb);
    void on_udp_accept(udp_pcb* pcb);
    void erase_tcp_session(std::uint32_t id);
    void erase_udp_session(std::uint32_t id);

    static err_t netif_init_handler(netif* interface_);
    static err_t netif_output_v4_handler(netif* interface_, pbuf* packet, const ip4_addr_t* address);
    static err_t netif_output_v6_handler(netif* interface_, pbuf* packet, const ip6_addr_t* address);
    static err_t tcp_accept_handler(void* argument, tcp_pcb* pcb, err_t error);
    static void udp_recv_handler(void* argument, udp_pcb* pcb, pbuf* packet, const ip_addr_t* address, u16_t port);

    const app::config& configuration_;
    tun_device device_;
    boost::asio::posix::stream_descriptor tun_stream_;
    netif netif_{};
    tcp_pcb* tcp_listener_ = nullptr;
    udp_pcb* udp_listener_ = nullptr;
    std::unordered_map<std::uint32_t, std::shared_ptr<tun_tcp_session>> tcp_sessions_;
    std::unordered_map<std::uint32_t, std::shared_ptr<tun_udp_session>> udp_sessions_;
    std::uint32_t next_session_id_ = 1;
    std::atomic_bool stopping_{false};
    bool stack_ready_ = false;
};

}    // namespace rv::tun

#endif    // REALITY_VISION_TUN_INBOUND_HPP

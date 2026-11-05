#ifndef REALITY_VISION_TUN_UDP_SESSION_HPP
#define REALITY_VISION_TUN_UDP_SESSION_HPP

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/experimental/channel.hpp>
#include <boost/asio/ip/udp.hpp>

#include "config.hpp"
#include "proxy_common.hpp"
#include "tun_lwip.hpp"

namespace rv::tun
{

// 一个会话对应一个客户端源地址（lwIP pretend pcb 只按源地址匹配），
// 会话内所有目的地址共用一条 XUDP 连接，逐包携带目的地址。
class tun_udp_session : public std::enable_shared_from_this<tun_udp_session>
{
   public:
    tun_udp_session(boost::asio::any_io_executor executor,
                    const app::config& configuration,
                    udp_pcb* pcb,
                    std::string session_id,
                    std::function<void()> on_close);

    [[nodiscard]] boost::asio::awaitable<void> start();
    void stop();

    static void on_recv(void* argument, udp_pcb* pcb, pbuf* packet, const ip_addr_t* address, u16_t port);

   private:
    struct uplink_datagram
    {
        xudp::endpoint destination;
        std::vector<std::uint8_t> payload;
    };
    using packet_channel = boost::asio::experimental::channel<void(boost::system::error_code, uplink_datagram)>;

    [[nodiscard]] boost::asio::awaitable<void> run();
    [[nodiscard]] boost::asio::awaitable<void> packets_to_upstream(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(boost::system::error_code& ec);
    void enqueue_packet(pbuf* packet, const boost::asio::ip::udp::endpoint& target);
    void close();

    boost::asio::any_io_executor executor_;
    const app::config& configuration_;
    udp_pcb* pcb_ = nullptr;
    boost::asio::ip::udp::endpoint client_;
    std::string session_id_;
    std::function<void()> on_close_;
    packet_channel packets_;
    std::optional<xudp::xudp_stream> upstream_;
    std::chrono::steady_clock::time_point last_activity_{std::chrono::steady_clock::now()};
    bool stopped_ = false;
};

}    // namespace rv::tun

#endif    // REALITY_VISION_TUN_UDP_SESSION_HPP

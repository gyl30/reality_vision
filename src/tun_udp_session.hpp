#ifndef REALITY_VISION_TUN_UDP_SESSION_HPP
#define REALITY_VISION_TUN_UDP_SESSION_HPP

#include <atomic>
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
#include <boost/asio/steady_timer.hpp>

#include "config.hpp"
#include "proxy_common.hpp"
#include "tun_lwip.hpp"

namespace rv::tun
{

class tun_udp_session : public std::enable_shared_from_this<tun_udp_session>
{
   public:
    using packet_channel = boost::asio::experimental::channel<void(boost::system::error_code, std::vector<std::uint8_t>)>;

    tun_udp_session(boost::asio::any_io_executor executor,
                    const app::config& configuration,
                    udp_pcb* pcb,
                    boost::asio::ip::udp::endpoint client,
                    boost::asio::ip::udp::endpoint target,
                    std::uint32_t id,
                    std::string session_id,
                    std::function<void()> on_close);

    [[nodiscard]] boost::asio::awaitable<void> start();
    void stop();

    static void on_recv(void* argument, udp_pcb* pcb, pbuf* packet, const ip_addr_t* address, u16_t port);

   private:
    [[nodiscard]] boost::asio::awaitable<void> run();
    [[nodiscard]] boost::asio::awaitable<void> packets_to_upstream(vless::vless_udp_stream& upstream,
                                                                   boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(vless::vless_udp_stream& upstream,
                                                                   boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    void enqueue_packet(pbuf* packet);
    void close();
    void notify_closed();

    const app::config& configuration_;
    udp_pcb* pcb_ = nullptr;
    boost::asio::ip::udp::endpoint client_;
    boost::asio::ip::udp::endpoint target_endpoint_;
    proxy::target target_;
    std::uint32_t id_;
    std::string session_id_;
    std::function<void()> on_close_;
    packet_channel packets_;
    boost::asio::steady_timer idle_timer_;
    std::optional<vless::vless_udp_stream> upstream_;
    std::atomic_bool stopped_{false};
    std::chrono::steady_clock::time_point last_activity_{std::chrono::steady_clock::now()};
};

}    // namespace rv::tun

#endif    // REALITY_VISION_TUN_UDP_SESSION_HPP

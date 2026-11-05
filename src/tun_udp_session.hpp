#ifndef REALITY_VISION_TUN_UDP_SESSION_HPP
#define REALITY_VISION_TUN_UDP_SESSION_HPP

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
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

// 一个会话对应一个客户端源地址（lwIP pretend pcb 只按源地址匹配），
// 会话内每个目的地址使用独立的 VLESS UDP flow。
class tun_udp_session : public std::enable_shared_from_this<tun_udp_session>
{
   public:
    using packet_channel = boost::asio::experimental::channel<void(boost::system::error_code, std::vector<std::uint8_t>)>;

    tun_udp_session(boost::asio::any_io_executor executor,
                    const app::config& configuration,
                    udp_pcb* pcb,
                    std::string session_id,
                    std::function<void()> on_close);

    [[nodiscard]] boost::asio::awaitable<void> start();
    void stop();

    static void on_recv(void* argument, udp_pcb* pcb, pbuf* packet, const ip_addr_t* address, u16_t port);

   private:
    struct flow
    {
        flow(boost::asio::any_io_executor executor, boost::asio::ip::udp::endpoint target_endpoint, std::string flow_id);

        boost::asio::ip::udp::endpoint target;
        std::string id;
        packet_channel packets;
        std::optional<vless::vless_udp_stream> upstream;
        std::chrono::steady_clock::time_point last_activity{std::chrono::steady_clock::now()};
        bool closed = false;
    };

    [[nodiscard]] boost::asio::awaitable<void> run_flow(std::shared_ptr<flow> current);
    [[nodiscard]] boost::asio::awaitable<void> packets_to_upstream(flow& current, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(flow& current, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> idle_watchdog();
    void enqueue_packet(pbuf* packet, const boost::asio::ip::udp::endpoint& target);
    void close_flow(flow& current);
    void close();

    boost::asio::any_io_executor executor_;
    const app::config& configuration_;
    udp_pcb* pcb_ = nullptr;
    boost::asio::ip::udp::endpoint client_;
    std::string session_id_;
    std::function<void()> on_close_;
    boost::asio::steady_timer idle_timer_;
    std::map<boost::asio::ip::udp::endpoint, std::shared_ptr<flow>> flows_;
    std::uint64_t next_flow_number_ = 1;
    bool stopped_ = false;
};

}    // namespace rv::tun

#endif    // REALITY_VISION_TUN_UDP_SESSION_HPP

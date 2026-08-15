#ifndef REALITY_VISION_TUN_TCP_SESSION_HPP
#define REALITY_VISION_TUN_TCP_SESSION_HPP

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

#include <boost/asio/awaitable.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/system/error_code.hpp>

#include "config.hpp"
#include "proxy_common.hpp"
#include "tun_lwip.hpp"

namespace rv::tun
{

class tun_tcp_session : public std::enable_shared_from_this<tun_tcp_session>
{
   public:
    tun_tcp_session(boost::asio::any_io_executor executor,
                    const app::config& configuration,
                    tcp_pcb* pcb,
                    std::uint32_t id,
                    std::string session_id,
                    std::function<void()> on_close);

    [[nodiscard]] boost::asio::awaitable<void> start();
    void stop();

    static err_t on_recv(void* argument, tcp_pcb* pcb, pbuf* packet, err_t error);
    static err_t on_sent(void* argument, tcp_pcb* pcb, u16_t length);
    static void on_err(void* argument, err_t error);
    static err_t on_poll(void* argument, tcp_pcb* pcb);

   private:
    [[nodiscard]] boost::asio::awaitable<void> run();
    [[nodiscard]] boost::asio::awaitable<void> client_to_upstream(vision::vision_stream& upstream,
                                                                  boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> upstream_to_client(vision::vision_stream& upstream,
                                                                  boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> wait_client_event();
    [[nodiscard]] boost::asio::awaitable<void> wait_send_event();
    void signal_client_event();
    void signal_send_event();
    void signal_all_events();
    void close_client(bool abort_connection);
    void notify_closed();

    const app::config& configuration_;
    tcp_pcb* pcb_ = nullptr;
    pbuf* pending_ = nullptr;
    std::uint32_t id_;
    std::string session_id_;
    proxy::target target_;
    std::function<void()> on_close_;
    boost::asio::steady_timer client_wait_timer_;
    boost::asio::steady_timer send_wait_timer_;
    std::optional<vision::vision_stream> upstream_;
    std::atomic_bool stopped_{false};
    bool peer_eof_ = false;
};

}    // namespace rv::tun

#endif    // REALITY_VISION_TUN_TCP_SESSION_HPP

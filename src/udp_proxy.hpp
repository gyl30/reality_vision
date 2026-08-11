#ifndef REALITY_VISION_UDP_PROXY_HPP
#define REALITY_VISION_UDP_PROXY_HPP

#include "config.hpp"
#include "socks5_protocol.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

#include <memory>
#include <string>

namespace rv::app
{
struct runtime_state;
}

namespace rv::udp_proxy
{

[[nodiscard]] boost::asio::awaitable<void> run_socks_association(boost::asio::ip::tcp::socket control_socket,
                                                                 app::config configuration,
                                                                 std::shared_ptr<app::runtime_state> runtime,
                                                                 socks5::request request,
                                                                 std::string session_id);

[[nodiscard]] boost::asio::ip::udp::socket create_tproxy_socket(boost::asio::any_io_executor executor,
                                                                std::uint16_t port,
                                                                boost::system::error_code& ec);

[[nodiscard]] boost::asio::awaitable<void> run_tproxy_server(boost::asio::ip::udp::socket socket,
                                                             app::config configuration,
                                                             std::shared_ptr<app::runtime_state> runtime,
                                                             boost::system::error_code& ec);

}    // namespace rv::udp_proxy

#endif    // REALITY_VISION_UDP_PROXY_HPP

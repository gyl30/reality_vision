#ifndef REALITY_VISION_TCP_PROXY_HPP
#define REALITY_VISION_TCP_PROXY_HPP

#include "config.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

namespace rv::tcp_proxy
{

boost::asio::awaitable<void> run_socks_server(boost::asio::ip::tcp::acceptor acceptor,
                                               app::config configuration,
                                               boost::system::error_code& ec);

boost::asio::awaitable<void> run_redirect_server(boost::asio::ip::tcp::acceptor acceptor,
                                                  app::config configuration,
                                                  boost::system::error_code& ec);

boost::asio::awaitable<void> run_tproxy_server(boost::asio::ip::tcp::acceptor acceptor,
                                                app::config configuration,
                                                boost::system::error_code& ec);

}    // namespace rv::tcp_proxy

#endif    // REALITY_VISION_TCP_PROXY_HPP

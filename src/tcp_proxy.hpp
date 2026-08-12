#ifndef REALITY_VISION_TCP_PROXY_HPP
#define REALITY_VISION_TCP_PROXY_HPP

#include "config.hpp"
#include "listener_service.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>

namespace rv::tcp_proxy
{

class socks_session final : public std::enable_shared_from_this<socks_session>
{
   public:
    socks_session(boost::asio::ip::tcp::socket socket, app::config configuration, std::string session_id);

    void startup();

   private:
    void shutdown();
    boost::asio::awaitable<void> run();

    boost::asio::ip::tcp::socket socket_;
    app::config configuration_;
    std::string session_id_;
};

class redirect_session final : public std::enable_shared_from_this<redirect_session>
{
   public:
    redirect_session(boost::asio::ip::tcp::socket socket, app::config configuration, std::string session_id);

    void startup();

   private:
    void shutdown();
    boost::asio::awaitable<void> run();

    boost::asio::ip::tcp::socket socket_;
    app::config configuration_;
    std::string session_id_;
};

class tcp_tproxy_session final : public std::enable_shared_from_this<tcp_tproxy_session>
{
   public:
    tcp_tproxy_session(boost::asio::ip::tcp::socket socket, app::config configuration, std::string session_id);

    void startup();

   private:
    void shutdown();
    boost::asio::awaitable<void> run();

    boost::asio::ip::tcp::socket socket_;
    app::config configuration_;
    std::string session_id_;
};

class socks_service final : public app::listener_service, public std::enable_shared_from_this<socks_service>
{
   public:
    socks_service(boost::asio::ip::tcp::acceptor acceptor, app::config configuration, std::string service_id);

    void startup() override;

   private:
    void shutdown();
    boost::asio::awaitable<void> accept_connections();

    boost::asio::ip::tcp::acceptor acceptor_;
    app::config configuration_;
    std::string service_id_;
    std::uint64_t next_session_number_{1};
    bool stopping_{false};
};

class redirect_service final : public app::listener_service, public std::enable_shared_from_this<redirect_service>
{
   public:
    redirect_service(boost::asio::ip::tcp::acceptor acceptor, app::config configuration, std::string service_id);

    void startup() override;

   private:
    void shutdown();
    boost::asio::awaitable<void> accept_connections();

    boost::asio::ip::tcp::acceptor acceptor_;
    app::config configuration_;
    std::string service_id_;
    std::uint64_t next_session_number_{1};
    bool stopping_{false};
};

class tcp_tproxy_service final : public app::listener_service, public std::enable_shared_from_this<tcp_tproxy_service>
{
   public:
    tcp_tproxy_service(boost::asio::ip::tcp::acceptor acceptor, app::config configuration, std::string service_id);

    void startup() override;

   private:
    void shutdown();
    boost::asio::awaitable<void> accept_connections();

    boost::asio::ip::tcp::acceptor acceptor_;
    app::config configuration_;
    std::string service_id_;
    std::uint64_t next_session_number_{1};
    bool stopping_{false};
};

}    // namespace rv::tcp_proxy

#endif    // REALITY_VISION_TCP_PROXY_HPP

#ifndef REALITY_VISION_TCP_PROXY_HPP
#define REALITY_VISION_TCP_PROXY_HPP

#include "config.hpp"
#include "proxy_service.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <cstddef>
#include <cstdint>
#include <exception>
#include <memory>
#include <string>

namespace rv::tcp_proxy
{

namespace detail
{

class tcp_session : public std::enable_shared_from_this<tcp_session>
{
   public:
    tcp_session(boost::asio::ip::tcp::socket socket, app::config configuration, std::string session_id);
    virtual ~tcp_session() = default;

    void startup();

   protected:
    virtual boost::asio::awaitable<void> run() = 0;

    boost::asio::ip::tcp::socket socket_;
    app::config configuration_;
    std::string session_id_;

   private:
    void shutdown();
};

}    // namespace detail

class socks_session final : public detail::tcp_session
{
   public:
    using tcp_session::tcp_session;

   private:
    boost::asio::awaitable<void> run() override;
};

class redirect_session final : public detail::tcp_session
{
   public:
    using tcp_session::tcp_session;

   private:
    boost::asio::awaitable<void> run() override;
};

class tcp_tproxy_session final : public detail::tcp_session
{
   public:
    using tcp_session::tcp_session;

   private:
    boost::asio::awaitable<void> run() override;
};

class socks_proxy final : public app::proxy_service, public std::enable_shared_from_this<socks_proxy>
{
   public:
    socks_proxy(boost::asio::ip::tcp::acceptor acceptor, app::config configuration, std::string service_id);

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

class redirect_proxy final : public app::proxy_service, public std::enable_shared_from_this<redirect_proxy>
{
   public:
    redirect_proxy(boost::asio::ip::tcp::acceptor acceptor, app::config configuration, std::string service_id);

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

class tcp_tproxy final : public app::proxy_service, public std::enable_shared_from_this<tcp_tproxy>
{
   public:
    tcp_tproxy(boost::asio::ip::tcp::acceptor acceptor, app::config configuration, std::string service_id);

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

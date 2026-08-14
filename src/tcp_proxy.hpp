#ifndef REALITY_VISION_TCP_PROXY_HPP
#define REALITY_VISION_TCP_PROXY_HPP

#include <memory>
#include <string>
#include <cstdint>

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/awaitable.hpp>

#include "config.hpp"
#include "proxy_service.hpp"

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

namespace detail
{

class tcp_listener : public app::proxy_service
{
   public:
    tcp_listener(boost::asio::ip::tcp::acceptor acceptor, app::config configuration, std::string service_id);

    void startup() override;

   protected:
    virtual boost::asio::awaitable<void> accept_connections() = 0;
    std::string next_session_id();

    boost::asio::ip::tcp::acceptor acceptor_;
    app::config configuration_;
    std::string service_id_;

   private:
    std::uint64_t next_session_number_{1};
};

}    // namespace detail

class socks_proxy final : public detail::tcp_listener
{
   public:
    using tcp_listener::tcp_listener;

   private:
    boost::asio::awaitable<void> accept_connections() override;
};

class redirect_proxy final : public detail::tcp_listener
{
   public:
    using tcp_listener::tcp_listener;

   private:
    boost::asio::awaitable<void> accept_connections() override;
};

class tcp_tproxy final : public detail::tcp_listener
{
   public:
    using tcp_listener::tcp_listener;

   private:
    boost::asio::awaitable<void> accept_connections() override;
};

}    // namespace rv::tcp_proxy

#endif    // REALITY_VISION_TCP_PROXY_HPP

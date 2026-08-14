#ifndef REALITY_VISION_UDP_PROXY_HPP
#define REALITY_VISION_UDP_PROXY_HPP

#include "config.hpp"
#include "proxy_service.hpp"
#include "socks5_protocol.hpp"

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <string>

namespace rv::udp_proxy
{

class udp_tproxy_session;

[[nodiscard]] boost::asio::awaitable<void> run_socks_association(boost::asio::ip::tcp::socket& control_socket,
                                                                 app::config configuration,
                                                                 socks5::request request,
                                                                 std::string session_id);

[[nodiscard]] boost::asio::ip::udp::socket create_tproxy_socket(boost::asio::any_io_executor executor,
                                                                std::uint16_t port,
                                                                bool enable_reuse_port,
                                                                boost::system::error_code& ec);

class udp_tproxy final : public app::proxy_service
{
   public:
    udp_tproxy(boost::asio::ip::udp::socket socket, app::config configuration, std::string service_id);

    void startup() override;

   private:
    boost::asio::awaitable<void> receive_datagrams();
    std::shared_ptr<udp_tproxy_session> get_session(const boost::asio::ip::udp::endpoint& client,
                                                    const boost::asio::ip::udp::endpoint& destination,
                                                    boost::system::error_code& ec);

    boost::asio::ip::udp::socket socket_;
    app::config configuration_;
    std::string service_id_;
    std::map<std::string, std::weak_ptr<udp_tproxy_session>> sessions_;
    std::uint64_t next_session_number_{1};
};

}    // namespace rv::udp_proxy

#endif    // REALITY_VISION_UDP_PROXY_HPP

#ifndef REALITY_VISION_TRANSPARENT_HPP
#define REALITY_VISION_TRANSPARENT_HPP

#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

namespace rv::transparent
{

[[nodiscard]] boost::system::error_code enable_ipv4_transparent(boost::asio::ip::tcp::acceptor& acceptor) noexcept;
[[nodiscard]] boost::system::error_code get_redirect_original_destination(boost::asio::ip::tcp::socket& socket,
                                                                          boost::asio::ip::tcp::endpoint& destination) noexcept;

}    // namespace rv::transparent

#endif    // REALITY_VISION_TRANSPARENT_HPP

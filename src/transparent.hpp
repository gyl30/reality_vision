#ifndef REALITY_VISION_TRANSPARENT_HPP
#define REALITY_VISION_TRANSPARENT_HPP

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace rv::transparent
{

[[nodiscard]] boost::system::error_code enable_ipv4_transparent(boost::asio::ip::tcp::acceptor& acceptor) noexcept;
[[nodiscard]] boost::system::error_code enable_ipv4_transparent(boost::asio::ip::udp::socket& socket) noexcept;
[[nodiscard]] boost::system::error_code enable_ipv4_original_destination(boost::asio::ip::udp::socket& socket) noexcept;
[[nodiscard]] boost::system::error_code get_redirect_original_destination(boost::asio::ip::tcp::socket& socket,
                                                                          boost::asio::ip::tcp::endpoint& destination) noexcept;

[[nodiscard]] std::optional<std::size_t> receive_ipv4_original_datagram(boost::asio::ip::udp::socket& socket,
                                                                         std::span<std::uint8_t> output,
                                                                         boost::asio::ip::udp::endpoint& source,
                                                                         boost::asio::ip::udp::endpoint& destination,
                                                                         boost::system::error_code& ec) noexcept;

}    // namespace rv::transparent

#endif    // REALITY_VISION_TRANSPARENT_HPP

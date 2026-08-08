#ifndef REALITY_VISION_SOCKS5_PROTOCOL_HPP
#define REALITY_VISION_SOCKS5_PROTOCOL_HPP

#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ip/udp.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <variant>
#include <vector>

namespace rv::socks5
{

struct ipv4_address
{
    std::array<std::uint8_t, 4> bytes{};
};

struct ipv6_address
{
    std::array<std::uint8_t, 16> bytes{};
};

struct domain_address
{
    std::string name;
};

using address = std::variant<ipv4_address, domain_address, ipv6_address>;

enum class command : std::uint8_t
{
    kConnect = 0x01,
    kUdpAssociate = 0x03,
};

struct request
{
    command requested_command{command::kConnect};
    address destination;
    std::uint16_t port{};
};

struct udp_datagram
{
    address destination;
    std::uint16_t port{};
    std::span<const std::uint8_t> payload;
};

struct credentials
{
    std::string username;
    std::string password;
};

enum class reply : std::uint8_t
{
    kSucceeded = 0x00,
    kGeneralFailure = 0x01,
    kNetworkUnreachable = 0x03,
    kHostUnreachable = 0x04,
    kConnectionRefused = 0x05,
    kTtlExpired = 0x06,
    kCommandNotSupported = 0x07,
    kAddressTypeNotSupported = 0x08,
};

[[nodiscard]] boost::system::error_code decode_request(std::span<const std::uint8_t> request_bytes, request& output);
[[nodiscard]] boost::system::error_code decode_udp_datagram(std::span<const std::uint8_t> packet, udp_datagram& output);
[[nodiscard]] std::array<std::uint8_t, 10> encode_reply(reply value) noexcept;
[[nodiscard]] std::vector<std::uint8_t> encode_udp_datagram(const address& source,
                                                            std::uint16_t port,
                                                            std::span<const std::uint8_t> payload,
                                                            boost::system::error_code& ec);
[[nodiscard]] std::string format_destination(const address& destination, std::uint16_t port);
[[nodiscard]] std::string format_destination(const request& request);

[[nodiscard]] boost::asio::awaitable<std::optional<request>> negotiate(boost::asio::ip::tcp::socket& socket,
                                                                       const std::optional<credentials>& expected_credentials,
                                                                       boost::system::error_code& ec);
[[nodiscard]] boost::asio::awaitable<void> send_reply(boost::asio::ip::tcp::socket& socket,
                                                       reply value,
                                                       boost::system::error_code& ec);
[[nodiscard]] boost::asio::awaitable<void> send_reply(boost::asio::ip::tcp::socket& socket,
                                                       reply value,
                                                       const boost::asio::ip::udp::endpoint& bound_endpoint,
                                                       boost::system::error_code& ec);

}    // namespace rv::socks5

#endif

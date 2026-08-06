#ifndef REALITY_VISION_VLESS_HEADER_HPP
#define REALITY_VISION_VLESS_HEADER_HPP

#include <boost/system/error_code.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <variant>
#include <vector>

namespace rv::vless
{

struct ipv4_address { std::array<std::uint8_t, 4> bytes{}; };
struct ipv6_address { std::array<std::uint8_t, 16> bytes{}; };
struct domain_address { std::string name; };
using address = std::variant<ipv4_address, domain_address, ipv6_address>;

struct client_config
{
    std::array<std::uint8_t, 16> user_id{};
    address destination;
    std::uint16_t destination_port{};
};

[[nodiscard]] std::vector<std::uint8_t> encode_tcp_request(
    const client_config& config, boost::system::error_code& ec);

} // namespace rv::vless

#endif

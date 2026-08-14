#ifndef REALITY_VISION_VLESS_HEADER_HPP
#define REALITY_VISION_VLESS_HEADER_HPP

#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/system/error_code.hpp>

#include "network_address.hpp"

namespace rv::vless
{

inline constexpr std::size_t kUserIdSize = 16;

struct client_config
{
    std::array<std::uint8_t, kUserIdSize> user_id{};
    net::address destination;
    std::uint16_t destination_port{};
};

[[nodiscard]] std::vector<std::uint8_t> encode_tcp_request(const client_config& configuration, boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> encode_udp_request(const client_config& configuration, boost::system::error_code& ec);

}    // namespace rv::vless

#endif    // REALITY_VISION_VLESS_HEADER_HPP

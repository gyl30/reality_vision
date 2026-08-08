#ifndef REALITY_VISION_VLESS_HEADER_HPP
#define REALITY_VISION_VLESS_HEADER_HPP

#include <boost/system/error_code.hpp>

#include "network_address.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace rv::vless
{

struct client_config
{
    std::array<std::uint8_t, 16> user_id{};
    net::address destination;
    std::uint16_t destination_port{};
};

[[nodiscard]] std::vector<std::uint8_t> encode_tcp_request(const client_config& configuration, boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> encode_udp_request(const client_config& configuration, boost::system::error_code& ec);

}    // namespace rv::vless

#endif

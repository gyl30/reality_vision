#ifndef REALITY_VISION_NETWORK_ADDRESS_HPP
#define REALITY_VISION_NETWORK_ADDRESS_HPP

#include <array>
#include <cstdint>
#include <string>
#include <variant>

namespace rv::net
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

[[nodiscard]] std::string format_address_port(const address& value, std::uint16_t port);

}    // namespace rv::net

#endif    // REALITY_VISION_NETWORK_ADDRESS_HPP

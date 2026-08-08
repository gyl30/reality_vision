#ifndef REALITY_VISION_RV_REALITY_CONFIG_HPP
#define REALITY_VISION_RV_REALITY_CONFIG_HPP

#include <array>
#include <cstdint>
#include <string>

namespace rv::reality
{

enum class client_hello_profile
{
    firefox_120,
};

struct client_version
{
    std::uint8_t major{26};
    std::uint8_t minor{7};
    std::uint8_t patch{28};
};

struct client_config
{
    std::string server_name;
    std::array<std::uint8_t, 32> server_public_key{};
    std::array<std::uint8_t, 8> short_id{};
    client_version version{};
    client_hello_profile profile{client_hello_profile::firefox_120};
};

}    // namespace rv::reality

#endif    // REALITY_VISION_RV_REALITY_CONFIG_HPP

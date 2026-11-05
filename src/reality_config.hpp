#ifndef REALITY_VISION_RV_REALITY_CONFIG_HPP
#define REALITY_VISION_RV_REALITY_CONFIG_HPP

#include <array>
#include <string>
#include <cstddef>
#include <cstdint>

#include "crypto.hpp"

namespace rv::reality
{

inline constexpr std::size_t kShortIdSize = 8;

enum class client_hello_profile
{
    kFirefox148,
};

struct client_version
{
    std::uint8_t major{26};
    std::uint8_t minor{10};
    std::uint8_t patch{31};
};

struct client_config
{
    std::string server_name;
    std::array<std::uint8_t, crypto::kX25519KeySize> server_public_key{};
    std::array<std::uint8_t, kShortIdSize> short_id{};
    client_version version{};
    client_hello_profile profile{client_hello_profile::kFirefox148};
};

}    // namespace rv::reality

#endif    // REALITY_VISION_RV_REALITY_CONFIG_HPP

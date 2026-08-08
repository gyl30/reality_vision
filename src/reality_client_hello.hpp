#ifndef REALITY_VISION_REALITY_CLIENT_HELLO_HPP
#define REALITY_VISION_REALITY_CLIENT_HELLO_HPP

#include "reality_config.hpp"

#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

namespace rv::reality
{

struct client_hello_material
{
    std::vector<std::uint8_t> handshake_bytes;
    std::array<std::uint8_t, 32> client_random{};
    std::array<std::uint8_t, 32> session_id{};
    std::array<std::uint8_t, 32> x25519_private_key{};
    std::array<std::uint8_t, 32> reality_auth_key{};
};

[[nodiscard]] std::optional<client_hello_material> build_client_hello(
    const client_config& configuration,
    boost::system::error_code& ec,
    std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

[[nodiscard]] std::vector<std::uint8_t> wrap_plain_record(
    std::uint8_t content_type,
    std::span<const std::uint8_t> payload,
    boost::system::error_code& ec);

}    // namespace rv::reality

#endif

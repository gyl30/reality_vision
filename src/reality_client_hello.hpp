#ifndef REALITY_VISION_REALITY_CLIENT_HELLO_HPP
#define REALITY_VISION_REALITY_CLIENT_HELLO_HPP

#include "crypto.hpp"
#include "reality_config.hpp"
#include "tls_constants.hpp"

#include <boost/system/error_code.hpp>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <vector>

namespace rv::reality
{

inline constexpr std::size_t kRealitySessionIdSize = 32;

struct client_hello_material
{
    std::vector<std::uint8_t> handshake_bytes;
    std::array<std::uint8_t, tls::kRandomSize> client_random{};
    std::array<std::uint8_t, kRealitySessionIdSize> session_id{};
    std::array<std::uint8_t, crypto::kX25519KeySize> x25519_private_key{};
    std::array<std::uint8_t, crypto::kAes256GcmKeySize> reality_auth_key{};
};

[[nodiscard]] std::optional<client_hello_material> build_client_hello(const client_config& configuration,
                                                                      boost::system::error_code& ec,
                                                                      std::chrono::system_clock::time_point now = std::chrono::system_clock::now());

[[nodiscard]] std::vector<std::uint8_t> wrap_client_hello_record(std::span<const std::uint8_t> payload, boost::system::error_code& ec);

}    // namespace rv::reality

#endif    // REALITY_VISION_REALITY_CLIENT_HELLO_HPP

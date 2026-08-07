#ifndef REALITY_VISION_REALITY_RECORD_HPP
#define REALITY_VISION_REALITY_RECORD_HPP

#include "crypto.hpp"

#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace rv::reality
{

inline constexpr std::uint8_t tls_record_change_cipher_spec = 20;
inline constexpr std::uint8_t tls_record_alert = 21;
inline constexpr std::uint8_t tls_record_handshake = 22;
inline constexpr std::uint8_t tls_record_application_data = 23;

inline constexpr std::size_t max_tls_plaintext = 16U * 1024U;
inline constexpr std::size_t max_tls_ciphertext = max_tls_plaintext + 256U;

enum class cipher_suite : std::uint16_t
{
    unknown,
    tls_aes_128_gcm_sha256 = 0x1301,
    tls_aes_256_gcm_sha384 = 0x1302,
    tls_chacha20_poly1305_sha256 = 0x1303,
};

struct cipher_suite_properties
{
    crypto::hash_algorithm hash;
    crypto::aead_algorithm aead;
    std::size_t key_length;
};

[[nodiscard]] cipher_suite parse_cipher_suite(std::uint16_t value, boost::system::error_code& ec);
[[nodiscard]] cipher_suite_properties cipher_properties(cipher_suite suite) noexcept;

struct opened_record
{
    std::uint8_t inner_type{};
    std::vector<std::uint8_t> content;
};

class record_key
{
public:
    record_key(cipher_suite suite, std::span<const std::uint8_t> traffic_secret, boost::system::error_code& ec);

    record_key(const record_key&) = delete;
    record_key& operator=(const record_key&) = delete;
    record_key(record_key&&) noexcept = default;
    record_key& operator=(record_key&&) noexcept = default;

    [[nodiscard]] std::vector<std::uint8_t> seal(
        std::uint8_t inner_type,
        std::span<const std::uint8_t> plaintext,
        boost::system::error_code& ec);
    [[nodiscard]] opened_record open(
        std::span<const std::uint8_t, 5> header,
        std::span<const std::uint8_t> ciphertext,
        boost::system::error_code& ec);

private:
    [[nodiscard]] std::array<std::uint8_t, 12> next_nonce(boost::system::error_code& ec);

    crypto::aead cipher_;
    std::array<std::uint8_t, 12> iv_{};
    std::uint64_t sequence_{0};
    bool sequence_exhausted_{false};
};

struct handshake_secrets
{
    record_key client_key;
    record_key server_key;
    std::vector<std::uint8_t> client_secret;
    std::vector<std::uint8_t> server_secret;
    std::vector<std::uint8_t> master_secret;
};

struct application_keys
{
    record_key client_key;
    record_key server_key;
};

[[nodiscard]] std::optional<handshake_secrets> derive_handshake_secrets(
    cipher_suite suite,
    std::span<const std::uint8_t> shared_secret,
    std::span<const std::uint8_t> transcript,
    boost::system::error_code& ec);
[[nodiscard]] std::optional<application_keys> derive_application_keys(
    cipher_suite suite,
    std::span<const std::uint8_t> master_secret,
    std::span<const std::uint8_t> transcript,
    boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> finished_verify_data(
    cipher_suite suite,
    std::span<const std::uint8_t> traffic_secret,
    std::span<const std::uint8_t> transcript,
    boost::system::error_code& ec);

[[nodiscard]] std::vector<std::uint8_t> hkdf_expand_label(
    crypto::hash_algorithm hash,
    std::span<const std::uint8_t> secret,
    std::span<const std::uint8_t> label,
    std::span<const std::uint8_t> context,
    std::size_t output_length,
    boost::system::error_code& ec);

} // namespace rv::reality

#endif

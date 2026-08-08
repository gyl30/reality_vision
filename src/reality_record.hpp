#ifndef REALITY_VISION_REALITY_RECORD_HPP
#define REALITY_VISION_REALITY_RECORD_HPP

#include "crypto.hpp"
#include "tls_constants.hpp"

#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace rv::reality
{

enum class cipher_suite : std::uint16_t
{
    kUnknown,
    kTlsAes128GcmSha256 = 0x1301,
    kTlsAes256GcmSha384 = 0x1302,
    kTlsChacha20Poly1305Sha256 = 0x1303,
};

struct cipher_suite_properties
{
    crypto::hash_algorithm hash;
    crypto::aead_algorithm aead;
    std::size_t key_length;
};

[[nodiscard]] cipher_suite parse_cipher_suite(std::uint16_t value, boost::system::error_code& ec);
[[nodiscard]] cipher_suite_properties cipher_properties(cipher_suite suite) noexcept;
[[nodiscard]] bool is_valid_record_payload_size(std::uint8_t outer_type, std::size_t payload_size) noexcept;
[[nodiscard]] std::size_t parse_handshake_message_size(std::span<const std::uint8_t> header, boost::system::error_code& ec);
[[nodiscard]] bool is_valid_handshake_fragment(std::uint8_t content_type, std::span<const std::uint8_t> fragment, bool continuation_pending) noexcept;
[[nodiscard]] bool is_compatibility_change_cipher_spec(std::span<const std::uint8_t, tls::kRecordHeaderSize> header,
                                                       std::span<const std::uint8_t> payload) noexcept;
[[nodiscard]] std::optional<std::uint8_t> parse_alert_description(std::span<const std::uint8_t> content, boost::system::error_code& ec);

struct opened_record
{
    std::uint8_t inner_type{};
    std::vector<std::uint8_t> content;
};

class record_key
{
   public:
    record_key(cipher_suite suite, std::span<const std::uint8_t> traffic_secret, boost::system::error_code& ec);

    [[nodiscard]] std::vector<std::uint8_t> seal(std::uint8_t inner_type, std::span<const std::uint8_t> plaintext, boost::system::error_code& ec);
    [[nodiscard]] opened_record open(std::span<const std::uint8_t, tls::kRecordHeaderSize> header,
                                     std::span<const std::uint8_t> ciphertext,
                                     boost::system::error_code& ec);

   private:
    [[nodiscard]] std::array<std::uint8_t, tls::kRecordIvSize> next_nonce(boost::system::error_code& ec);

    crypto::aead cipher_;
    std::array<std::uint8_t, tls::kRecordIvSize> iv_{};
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

[[nodiscard]] std::optional<handshake_secrets> derive_handshake_secrets(cipher_suite suite,
                                                                        std::span<const std::uint8_t> shared_secret,
                                                                        std::span<const std::uint8_t> transcript,
                                                                        boost::system::error_code& ec);
[[nodiscard]] std::optional<application_keys> derive_application_keys(cipher_suite suite,
                                                                      std::span<const std::uint8_t> master_secret,
                                                                      std::span<const std::uint8_t> transcript,
                                                                      boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> finished_verify_data(cipher_suite suite,
                                                             std::span<const std::uint8_t> traffic_secret,
                                                             std::span<const std::uint8_t> transcript,
                                                             boost::system::error_code& ec);
void verify_finished_data(cipher_suite suite,
                          std::span<const std::uint8_t> traffic_secret,
                          std::span<const std::uint8_t> transcript,
                          std::span<const std::uint8_t> received,
                          boost::system::error_code& ec);

[[nodiscard]] std::vector<std::uint8_t> hkdf_expand_label(crypto::hash_algorithm hash,
                                                          std::span<const std::uint8_t> secret,
                                                          std::span<const std::uint8_t> label,
                                                          std::span<const std::uint8_t> context,
                                                          std::size_t output_length,
                                                          boost::system::error_code& ec);

}    // namespace rv::reality

#endif

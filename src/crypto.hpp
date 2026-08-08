#ifndef REALITY_VISION_CRYPTO_HPP
#define REALITY_VISION_CRYPTO_HPP

#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <span>
#include <vector>

namespace rv::crypto
{

enum class hash_algorithm { kSha256, kSha384, kSha512 };
enum class aead_algorithm { kAes128Gcm, kAes256Gcm, kChacha20Poly1305 };

struct x25519_key_pair
{
    std::array<std::uint8_t, 32> public_key{};
    std::array<std::uint8_t, 32> private_key{};
};

struct reality_certificate
{
    std::array<std::uint8_t, 32> ed25519_public_key{};
    std::vector<std::uint8_t> outer_signature;
};

void random_bytes(std::span<std::uint8_t> output, boost::system::error_code& ec);
void cleanse(std::span<std::uint8_t> value) noexcept;

[[nodiscard]] x25519_key_pair make_x25519_key_pair() noexcept;
[[nodiscard]] std::array<std::uint8_t, 32> x25519(
    std::span<const std::uint8_t, 32> private_key,
    std::span<const std::uint8_t, 32> peer_public_key,
    boost::system::error_code& ec);
[[nodiscard]] std::array<std::uint8_t, 65> make_p256_public_key(boost::system::error_code& ec);

[[nodiscard]] std::size_t hash_size(hash_algorithm algorithm) noexcept;
[[nodiscard]] std::vector<std::uint8_t> digest(
    hash_algorithm algorithm, std::span<const std::uint8_t> input, boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> hmac(
    hash_algorithm algorithm,
    std::span<const std::uint8_t> key,
    std::span<const std::uint8_t> input,
    boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> hkdf_extract(
    hash_algorithm algorithm,
    std::span<const std::uint8_t> salt,
    std::span<const std::uint8_t> input_key_material,
    boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> hkdf_expand(
    hash_algorithm algorithm,
    std::span<const std::uint8_t> pseudorandom_key,
    std::span<const std::uint8_t> info,
    std::size_t output_length,
    boost::system::error_code& ec);

[[nodiscard]] bool constant_time_equal(
    std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs) noexcept;

class aead
{
public:
    aead();
    aead(aead_algorithm algorithm, std::span<const std::uint8_t> key, boost::system::error_code& ec);
    ~aead();

    aead(const aead&) = delete;
    aead& operator=(const aead&) = delete;
    aead(aead&&) noexcept;
    aead& operator=(aead&&) noexcept;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::vector<std::uint8_t> seal(
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> plaintext,
        std::span<const std::uint8_t> additional_data,
        boost::system::error_code& ec) const;
    [[nodiscard]] std::vector<std::uint8_t> open(
        std::span<const std::uint8_t> nonce,
        std::span<const std::uint8_t> ciphertext,
        std::span<const std::uint8_t> additional_data,
        boost::system::error_code& ec) const;

private:
    class impl;
    std::unique_ptr<impl> impl_;
};

[[nodiscard]] reality_certificate parse_reality_certificate(
    std::span<const std::uint8_t> der, boost::system::error_code& ec);
void verify_ed25519(
    std::span<const std::uint8_t, 32> public_key,
    std::span<const std::uint8_t> message,
    std::span<const std::uint8_t> signature,
    boost::system::error_code& ec);

}    // namespace rv::crypto

#endif

#ifndef REALITY_VISION_CRYPTO_HPP
#define REALITY_VISION_CRYPTO_HPP

#include <span>
#include <array>
#include <memory>
#include <vector>
#include <cstddef>
#include <cstdint>

#include <boost/system/error_code.hpp>

namespace rv::crypto
{

inline constexpr std::size_t kX25519KeySize = 32;
inline constexpr std::size_t kP256PublicKeySize = 65;
inline constexpr std::size_t kMlkem768PublicKeySize = 1184;
inline constexpr std::size_t kMlkem768CiphertextSize = 1088;
inline constexpr std::size_t kMlkem768SeedSize = 64;
inline constexpr std::size_t kMlkemSharedSecretSize = 32;
inline constexpr std::size_t kEd25519PublicKeySize = 32;
inline constexpr std::size_t kEd25519SignatureSize = 64;
inline constexpr std::size_t kAes128GcmKeySize = 16;
inline constexpr std::size_t kAes256GcmKeySize = 32;
inline constexpr std::size_t kChacha20Poly1305KeySize = 32;
inline constexpr std::size_t kSha256DigestSize = 32;
inline constexpr std::size_t kSha384DigestSize = 48;
inline constexpr std::size_t kSha512DigestSize = 64;
inline constexpr std::size_t kAeadTagSize = 16;

enum class hash_algorithm
{
    kSha256,
    kSha384,
    kSha512
};
enum class aead_algorithm
{
    kAes128Gcm,
    kAes256Gcm,
    kChacha20Poly1305
};

struct x25519_key_pair
{
    std::array<std::uint8_t, kX25519KeySize> public_key{};
    std::array<std::uint8_t, kX25519KeySize> private_key{};
};

// 私钥以 seed 形式保存，避免在头文件中暴露 BoringSSL 的私钥结构。
struct mlkem768_key_pair
{
    std::array<std::uint8_t, kMlkem768PublicKeySize> public_key{};
    std::array<std::uint8_t, kMlkem768SeedSize> seed{};
};

struct mlkem768_encapsulation
{
    std::array<std::uint8_t, kMlkem768CiphertextSize> ciphertext{};
    std::array<std::uint8_t, kMlkemSharedSecretSize> shared_secret{};
};

struct reality_certificate
{
    std::array<std::uint8_t, kEd25519PublicKeySize> ed25519_public_key{};
    std::vector<std::uint8_t> outer_signature;
};

void random_bytes(std::span<std::uint8_t> output, boost::system::error_code& ec);
void cleanse(std::span<std::uint8_t> value) noexcept;

[[nodiscard]] x25519_key_pair make_x25519_key_pair() noexcept;
[[nodiscard]] std::array<std::uint8_t, kX25519KeySize> x25519(std::span<const std::uint8_t, kX25519KeySize> private_key,
                                                              std::span<const std::uint8_t, kX25519KeySize> peer_public_key,
                                                              boost::system::error_code& ec);
[[nodiscard]] std::array<std::uint8_t, kP256PublicKeySize> make_p256_public_key(boost::system::error_code& ec);

[[nodiscard]] mlkem768_key_pair make_mlkem768_key_pair() noexcept;
[[nodiscard]] std::array<std::uint8_t, kMlkemSharedSecretSize> mlkem768_decapsulate(std::span<const std::uint8_t, kMlkem768SeedSize> seed,
                                                                                    std::span<const std::uint8_t, kMlkem768CiphertextSize> ciphertext,
                                                                                    boost::system::error_code& ec);
[[nodiscard]] mlkem768_encapsulation mlkem768_encapsulate(std::span<const std::uint8_t, kMlkem768PublicKeySize> public_key,
                                                          boost::system::error_code& ec);

[[nodiscard]] std::size_t hash_size(hash_algorithm algorithm) noexcept;
[[nodiscard]] std::vector<std::uint8_t> digest(hash_algorithm algorithm, std::span<const std::uint8_t> input, boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> hmac(hash_algorithm algorithm,
                                             std::span<const std::uint8_t> key,
                                             std::span<const std::uint8_t> input,
                                             boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> hkdf_extract(hash_algorithm algorithm,
                                                     std::span<const std::uint8_t> salt,
                                                     std::span<const std::uint8_t> input_key_material,
                                                     boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> hkdf_expand(hash_algorithm algorithm,
                                                    std::span<const std::uint8_t> pseudorandom_key,
                                                    std::span<const std::uint8_t> info,
                                                    std::size_t output_length,
                                                    boost::system::error_code& ec);

[[nodiscard]] bool constant_time_equal(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs) noexcept;

class aead
{
   public:
    aead();
    aead(aead_algorithm algorithm, std::span<const std::uint8_t> key, boost::system::error_code& ec);
    ~aead();

    aead(aead&&) noexcept;
    aead& operator=(aead&&) noexcept;

    [[nodiscard]] bool valid() const noexcept;
    [[nodiscard]] std::vector<std::uint8_t> seal(std::span<const std::uint8_t> nonce,
                                                 std::span<const std::uint8_t> plaintext,
                                                 std::span<const std::uint8_t> additional_data,
                                                 boost::system::error_code& ec) const;
    [[nodiscard]] std::vector<std::uint8_t> open(std::span<const std::uint8_t> nonce,
                                                 std::span<const std::uint8_t> ciphertext,
                                                 std::span<const std::uint8_t> additional_data,
                                                 boost::system::error_code& ec) const;

   private:
    class impl;
    std::unique_ptr<impl> impl_;
};

[[nodiscard]] reality_certificate parse_reality_certificate(std::span<const std::uint8_t> der, boost::system::error_code& ec);
void verify_ed25519(std::span<const std::uint8_t, kEd25519PublicKeySize> public_key,
                    std::span<const std::uint8_t> message,
                    std::span<const std::uint8_t, kEd25519SignatureSize> signature,
                    boost::system::error_code& ec);

}    // namespace rv::crypto

#endif    // REALITY_VISION_CRYPTO_HPP

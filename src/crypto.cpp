#include <array>
#include <limits>
#include <string>

#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <openssl/nid.h>
#include <openssl/aead.h>
#include <openssl/base.h>
#include <openssl/hkdf.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/mlkem.h>
#include <openssl/bytestring.h>
#include <openssl/x509.h>
#include <spdlog/spdlog.h>
#include <openssl/crypto.h>
#include <openssl/ec_key.h>
#include <openssl/curve25519.h>
#include <boost/system/errc.hpp>

#include "crypto.hpp"

namespace rv::crypto
{
namespace
{

void discard_crypto_errors() noexcept
{
    while (ERR_get_error() != 0)
    {
    }
}

void set_crypto_error(boost::system::error_code& ec, boost::system::errc::errc_t value, const char* operation)
{
    ec = boost::system::errc::make_error_code(value);
    std::string details;
    while (const auto error = ERR_get_error())
    {
        std::array<char, 256> text{};
        ERR_error_string_n(error, text.data(), text.size());
        if (!details.empty())
        {
            details.append("; ");
        }
        details.append(text.data());
    }
    if (details.empty())
    {
        spdlog::error("{}", operation);
    }
    else
    {
        spdlog::error("{}: {}", operation, details);
    }
}

const EVP_MD* evp_md(hash_algorithm algorithm) noexcept
{
    switch (algorithm)
    {
        case hash_algorithm::kSha256:
            return EVP_sha256();
        case hash_algorithm::kSha384:
            return EVP_sha384();
        case hash_algorithm::kSha512:
            return EVP_sha512();
    }
    return nullptr;
}

const EVP_AEAD* evp_aead(aead_algorithm algorithm) noexcept
{
    switch (algorithm)
    {
        case aead_algorithm::kAes128Gcm:
            return EVP_aead_aes_128_gcm();
        case aead_algorithm::kAes256Gcm:
            return EVP_aead_aes_256_gcm();
        case aead_algorithm::kChacha20Poly1305:
            return EVP_aead_chacha20_poly1305();
    }
    return nullptr;
}

}    // namespace

void random_bytes(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (output.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::value_too_large);
        return;
    }
    if (output.empty())
    {
        return;
    }
    ERR_clear_error();
    if (RAND_bytes(output.data(), static_cast<int>(output.size())) != 1)
    {
        set_crypto_error(ec, boost::system::errc::io_error, "random byte generation failed");
    }
}

void cleanse(std::span<std::uint8_t> value) noexcept
{
    if (!value.empty())
    {
        OPENSSL_cleanse(value.data(), value.size());
    }
}

x25519_key_pair make_x25519_key_pair() noexcept
{
    x25519_key_pair result;
    X25519_keypair(result.public_key.data(), result.private_key.data());
    return result;
}

std::array<std::uint8_t, kX25519KeySize> x25519(std::span<const std::uint8_t, kX25519KeySize> private_key,
                                                std::span<const std::uint8_t, kX25519KeySize> peer_public_key,
                                                boost::system::error_code& ec)
{
    std::array<std::uint8_t, kX25519KeySize> result{};
    ERR_clear_error();
    if (X25519(result.data(), private_key.data(), peer_public_key.data()) != 1)
    {
        set_crypto_error(ec, boost::system::errc::bad_message, "x25519 failed");
    }
    return result;
}

std::array<std::uint8_t, kP256PublicKeySize> make_p256_public_key(boost::system::error_code& ec)
{
    std::array<std::uint8_t, kP256PublicKeySize> output{};
    ERR_clear_error();
    bssl::UniquePtr<EC_KEY> key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (!key || EC_KEY_generate_key(key.get()) != 1)
    {
        set_crypto_error(ec, boost::system::errc::io_error, "p-256 key generation failed");
        return output;
    }
    const auto written = EC_POINT_point2oct(
        EC_KEY_get0_group(key.get()), EC_KEY_get0_public_key(key.get()), POINT_CONVERSION_UNCOMPRESSED, output.data(), output.size(), nullptr);
    if (written != output.size())
    {
        set_crypto_error(ec, boost::system::errc::io_error, "p-256 public key encoding failed");
    }
    return output;
}

mlkem768_key_pair make_mlkem768_key_pair() noexcept
{
    static_assert(kMlkem768PublicKeySize == MLKEM768_PUBLIC_KEY_BYTES && kMlkem768SeedSize == MLKEM_SEED_BYTES);
    mlkem768_key_pair result;
    MLKEM768_private_key private_key;
    MLKEM768_generate_key(result.public_key.data(), result.seed.data(), &private_key);
    OPENSSL_cleanse(&private_key, sizeof(private_key));
    return result;
}

std::array<std::uint8_t, kMlkemSharedSecretSize> mlkem768_decapsulate(std::span<const std::uint8_t, kMlkem768SeedSize> seed,
                                                                      std::span<const std::uint8_t, kMlkem768CiphertextSize> ciphertext,
                                                                      boost::system::error_code& ec)
{
    static_assert(kMlkem768CiphertextSize == MLKEM768_CIPHERTEXT_BYTES && kMlkemSharedSecretSize == MLKEM_SHARED_SECRET_BYTES);
    std::array<std::uint8_t, kMlkemSharedSecretSize> result{};
    MLKEM768_private_key private_key;
    ERR_clear_error();
    if (MLKEM768_private_key_from_seed(&private_key, seed.data(), seed.size()) != 1 ||
        MLKEM768_decap(result.data(), ciphertext.data(), ciphertext.size(), &private_key) != 1)
    {
        set_crypto_error(ec, boost::system::errc::bad_message, "ml-kem-768 decapsulation failed");
    }
    OPENSSL_cleanse(&private_key, sizeof(private_key));
    return result;
}

mlkem768_encapsulation mlkem768_encapsulate(std::span<const std::uint8_t, kMlkem768PublicKeySize> public_key, boost::system::error_code& ec)
{
    mlkem768_encapsulation result;
    MLKEM768_public_key parsed_key;
    CBS input;
    CBS_init(&input, public_key.data(), public_key.size());
    ERR_clear_error();
    if (MLKEM768_parse_public_key(&parsed_key, &input) != 1)
    {
        set_crypto_error(ec, boost::system::errc::bad_message, "ml-kem-768 public key parse failed");
        return result;
    }
    MLKEM768_encap(result.ciphertext.data(), result.shared_secret.data(), &parsed_key);
    return result;
}

std::size_t hash_size(hash_algorithm algorithm) noexcept
{
    switch (algorithm)
    {
        case hash_algorithm::kSha256:
            return kSha256DigestSize;
        case hash_algorithm::kSha384:
            return kSha384DigestSize;
        case hash_algorithm::kSha512:
            return kSha512DigestSize;
    }
    return 0;
}

std::vector<std::uint8_t> digest(hash_algorithm algorithm, std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    std::vector<std::uint8_t> output(hash_size(algorithm));
    const auto* md = evp_md(algorithm);
    if (!md)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    unsigned int written = 0;
    ERR_clear_error();
    if (EVP_Digest(input.data(), input.size(), output.data(), &written, md, nullptr) != 1 || written != output.size())
    {
        set_crypto_error(ec, boost::system::errc::io_error, "digest failed");
        return {};
    }
    return output;
}

std::vector<std::uint8_t> hmac(hash_algorithm algorithm,
                               std::span<const std::uint8_t> key,
                               std::span<const std::uint8_t> input,
                               boost::system::error_code& ec)
{
    if (key.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::value_too_large);
        return {};
    }
    const auto* md = evp_md(algorithm);
    if (!md)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    std::vector<std::uint8_t> output(hash_size(algorithm));
    unsigned int written = 0;
    ERR_clear_error();
    if (HMAC(md, key.data(), static_cast<int>(key.size()), input.data(), input.size(), output.data(), &written) == nullptr ||
        written != output.size())
    {
        set_crypto_error(ec, boost::system::errc::io_error, "hmac failed");
        return {};
    }
    return output;
}

std::vector<std::uint8_t> hkdf_extract(hash_algorithm algorithm,
                                       std::span<const std::uint8_t> salt,
                                       std::span<const std::uint8_t> input_key_material,
                                       boost::system::error_code& ec)
{
    const auto* md = evp_md(algorithm);
    if (!md)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    std::vector<std::uint8_t> output(hash_size(algorithm));
    std::size_t written = 0;
    ERR_clear_error();
    if (HKDF_extract(output.data(), &written, md, input_key_material.data(), input_key_material.size(), salt.data(), salt.size()) != 1 ||
        written != output.size())
    {
        set_crypto_error(ec, boost::system::errc::io_error, "hkdf extract failed");
        return {};
    }
    return output;
}

std::vector<std::uint8_t> hkdf_expand(hash_algorithm algorithm,
                                      std::span<const std::uint8_t> pseudorandom_key,
                                      std::span<const std::uint8_t> info,
                                      std::size_t output_length,
                                      boost::system::error_code& ec)
{
    const auto* md = evp_md(algorithm);
    if (!md)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    std::vector<std::uint8_t> output(output_length);
    if (output_length == 0)
    {
        return output;
    }
    ERR_clear_error();
    if (HKDF_expand(output.data(), output.size(), md, pseudorandom_key.data(), pseudorandom_key.size(), info.data(), info.size()) != 1)
    {
        set_crypto_error(ec, boost::system::errc::io_error, "hkdf expand failed");
        return {};
    }
    return output;
}

bool constant_time_equal(std::span<const std::uint8_t> lhs, std::span<const std::uint8_t> rhs) noexcept
{
    return lhs.size() == rhs.size() && (lhs.empty() || CRYPTO_memcmp(lhs.data(), rhs.data(), lhs.size()) == 0);
}

class aead::impl
{
   public:
    bssl::UniquePtr<EVP_AEAD_CTX> context;
};

aead::aead() = default;

aead::aead(aead_algorithm algorithm, std::span<const std::uint8_t> key, boost::system::error_code& ec) : impl_(std::make_unique<impl>())
{
    const auto* algorithm_impl = evp_aead(algorithm);
    if (!algorithm_impl)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        impl_.reset();
        return;
    }
    ERR_clear_error();
    impl_->context.reset(EVP_AEAD_CTX_new(algorithm_impl, key.data(), key.size(), EVP_AEAD_DEFAULT_TAG_LENGTH));
    if (!impl_->context)
    {
        set_crypto_error(ec, boost::system::errc::io_error, "aead context creation failed");
        impl_.reset();
    }
}

aead::~aead() = default;
aead::aead(aead&&) noexcept = default;
aead& aead::operator=(aead&&) noexcept = default;

bool aead::valid() const noexcept { return impl_ && impl_->context; }

std::vector<std::uint8_t> aead::seal(std::span<const std::uint8_t> nonce,
                                     std::span<const std::uint8_t> plaintext,
                                     std::span<const std::uint8_t> additional_data,
                                     boost::system::error_code& ec) const
{
    if (!valid())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::state_not_recoverable);
        return {};
    }
    std::vector<std::uint8_t> output(plaintext.size() + kAeadTagSize);
    std::size_t written = 0;
    ERR_clear_error();
    if (EVP_AEAD_CTX_seal(impl_->context.get(),
                          output.data(),
                          &written,
                          output.size(),
                          nonce.data(),
                          nonce.size(),
                          plaintext.data(),
                          plaintext.size(),
                          additional_data.data(),
                          additional_data.size()) != 1)
    {
        set_crypto_error(ec, boost::system::errc::io_error, "aead seal failed");
        return {};
    }
    output.resize(written);
    return output;
}

std::vector<std::uint8_t> aead::open(std::span<const std::uint8_t> nonce,
                                     std::span<const std::uint8_t> ciphertext,
                                     std::span<const std::uint8_t> additional_data,
                                     boost::system::error_code& ec) const
{
    if (!valid())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::state_not_recoverable);
        return {};
    }
    std::vector<std::uint8_t> output(ciphertext.size());
    std::size_t written = 0;
    ERR_clear_error();
    if (EVP_AEAD_CTX_open(impl_->context.get(),
                          output.data(),
                          &written,
                          output.size(),
                          nonce.data(),
                          nonce.size(),
                          ciphertext.data(),
                          ciphertext.size(),
                          additional_data.data(),
                          additional_data.size()) != 1)
    {
        discard_crypto_errors();
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }
    output.resize(written);
    return output;
}

reality_certificate parse_reality_certificate(std::span<const std::uint8_t> der, boost::system::error_code& ec)
{
    reality_certificate result;
    if (der.size() > static_cast<std::size_t>(std::numeric_limits<long>::max()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::value_too_large);
        return result;
    }

    ERR_clear_error();
    const auto* cursor = der.data();
    bssl::UniquePtr<X509> certificate(d2i_X509(nullptr, &cursor, static_cast<long>(der.size())));
    if (!certificate || cursor != der.data() + der.size())
    {
        set_crypto_error(ec, boost::system::errc::bad_message, "failed to parse reality leaf certificate");
        return result;
    }

    const auto* public_key = X509_get0_pubkey(certificate.get());
    if (!public_key || EVP_PKEY_id(public_key) != EVP_PKEY_ED25519)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return result;
    }

    std::size_t public_key_length = result.ed25519_public_key.size();
    if (EVP_PKEY_get_raw_public_key(public_key, result.ed25519_public_key.data(), &public_key_length) != 1 ||
        public_key_length != result.ed25519_public_key.size())
    {
        set_crypto_error(ec, boost::system::errc::io_error, "failed to extract ed25519 public key");
        return {};
    }

    const ASN1_BIT_STRING* signature = nullptr;
    X509_get0_signature(&signature, nullptr, certificate.get());
    if (!signature)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }
    const auto signature_length = ASN1_STRING_length(signature);
    const auto* signature_data = ASN1_STRING_get0_data(signature);
    if (signature_length <= 0 || !signature_data)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }
    result.outer_signature.assign(signature_data, signature_data + static_cast<std::size_t>(signature_length));
    return result;
}

void verify_ed25519(std::span<const std::uint8_t, kEd25519PublicKeySize> public_key,
                    std::span<const std::uint8_t> message,
                    std::span<const std::uint8_t, kEd25519SignatureSize> signature,
                    boost::system::error_code& ec)
{
    ERR_clear_error();
    bssl::UniquePtr<EVP_PKEY> key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, public_key.data(), public_key.size()));
    bssl::UniquePtr<EVP_MD_CTX> context(EVP_MD_CTX_new());
    if (!key || !context || EVP_DigestVerifyInit(context.get(), nullptr, nullptr, nullptr, key.get()) != 1)
    {
        set_crypto_error(ec, boost::system::errc::io_error, "ed25519 verification initialization failed");
        return;
    }

    const int result = EVP_DigestVerify(context.get(), signature.data(), signature.size(), message.data(), message.size());
    if (result == 1)
    {
        return;
    }
    if (result == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        ERR_clear_error();
        return;
    }
    set_crypto_error(ec, boost::system::errc::io_error, "ed25519 verification failed");
}

}    // namespace rv::crypto

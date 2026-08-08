#include "reality_record.hpp"

#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <limits>
#include <string_view>

namespace rv::reality
{
namespace
{

void put_u16(std::uint16_t value, std::vector<std::uint8_t>& output)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

std::vector<std::uint8_t> derive_secret(crypto::hash_algorithm hash,
                                        std::span<const std::uint8_t> secret,
                                        std::string_view label,
                                        std::span<const std::uint8_t> transcript_hash,
                                        boost::system::error_code& ec)
{
    const auto label_bytes = std::span(reinterpret_cast<const std::uint8_t*>(label.data()), label.size());
    return hkdf_expand_label(hash, secret, label_bytes, transcript_hash, crypto::hash_size(hash), ec);
}

}    // namespace

cipher_suite parse_cipher_suite(std::uint16_t value, boost::system::error_code& ec)
{
    ec.clear();
    switch (value)
    {
        case static_cast<std::uint16_t>(cipher_suite::kTlsAes128GcmSha256):
            return cipher_suite::kTlsAes128GcmSha256;
        case static_cast<std::uint16_t>(cipher_suite::kTlsAes256GcmSha384):
            return cipher_suite::kTlsAes256GcmSha384;
        case static_cast<std::uint16_t>(cipher_suite::kTlsChacha20Poly1305Sha256):
            return cipher_suite::kTlsChacha20Poly1305Sha256;
        default:
            ec = boost::system::errc::make_error_code(boost::system::errc::protocol_not_supported);
            return cipher_suite::kUnknown;
    }
}

cipher_suite_properties cipher_properties(cipher_suite suite) noexcept
{
    switch (suite)
    {
        case cipher_suite::kTlsAes128GcmSha256:
            return {crypto::hash_algorithm::kSha256, crypto::aead_algorithm::kAes128Gcm, 16};
        case cipher_suite::kTlsAes256GcmSha384:
            return {crypto::hash_algorithm::kSha384, crypto::aead_algorithm::kAes256Gcm, 32};
        case cipher_suite::kTlsChacha20Poly1305Sha256:
            return {crypto::hash_algorithm::kSha256, crypto::aead_algorithm::kChacha20Poly1305, 32};
        case cipher_suite::kUnknown:
            break;
    }
    return {crypto::hash_algorithm::kSha256, crypto::aead_algorithm::kAes128Gcm, 0};
}

std::vector<std::uint8_t> hkdf_expand_label(crypto::hash_algorithm hash,
                                            std::span<const std::uint8_t> secret,
                                            std::span<const std::uint8_t> label,
                                            std::span<const std::uint8_t> context,
                                            std::size_t output_length,
                                            boost::system::error_code& ec)
{
    ec.clear();
    if (output_length > std::numeric_limits<std::uint16_t>::max() || label.size() > 249 || context.size() > std::numeric_limits<std::uint8_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::value_too_large);
        return {};
    }

    std::vector<std::uint8_t> info;
    info.reserve(2 + 1 + 6 + label.size() + 1 + context.size());
    put_u16(static_cast<std::uint16_t>(output_length), info);
    info.push_back(static_cast<std::uint8_t>(6 + label.size()));
    constexpr std::array<std::uint8_t, 6> kPrefix{'t', 'l', 's', '1', '3', ' '};
    info.insert(info.end(), kPrefix.begin(), kPrefix.end());
    info.insert(info.end(), label.begin(), label.end());
    info.push_back(static_cast<std::uint8_t>(context.size()));
    info.insert(info.end(), context.begin(), context.end());
    return crypto::hkdf_expand(hash, secret, info, output_length, ec);
}

record_key::record_key(cipher_suite suite, std::span<const std::uint8_t> traffic_secret, boost::system::error_code& ec)
{
    ec.clear();
    const auto properties = cipher_properties(suite);
    if (properties.key_length == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_not_supported);
        return;
    }

    constexpr std::array<std::uint8_t, 3> kKeyLabel{'k', 'e', 'y'};
    auto key = hkdf_expand_label(properties.hash, traffic_secret, kKeyLabel, {}, properties.key_length, ec);
    if (ec)
    {
        return;
    }
    cipher_ = crypto::aead(properties.aead, key, ec);
    crypto::cleanse(key);
    if (ec)
    {
        return;
    }

    constexpr std::array<std::uint8_t, 2> kIvLabel{'i', 'v'};
    auto iv = hkdf_expand_label(properties.hash, traffic_secret, kIvLabel, {}, iv_.size(), ec);
    if (ec)
    {
        return;
    }
    std::copy(iv.begin(), iv.end(), iv_.begin());
    crypto::cleanse(iv);
}

std::array<std::uint8_t, 12> record_key::next_nonce(boost::system::error_code& ec)
{
    ec.clear();
    if (sequence_exhausted_)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::value_too_large);
        return {};
    }

    auto nonce = iv_;
    auto sequence = sequence_;
    sequence_exhausted_ = sequence_ == std::numeric_limits<std::uint64_t>::max();
    if (!sequence_exhausted_)
    {
        ++sequence_;
    }
    for (std::size_t index = 0; index < 8; ++index)
    {
        nonce[11 - index] ^= static_cast<std::uint8_t>(sequence);
        sequence >>= 8U;
    }
    return nonce;
}

std::vector<std::uint8_t> record_key::seal(std::uint8_t inner_type, std::span<const std::uint8_t> plaintext, boost::system::error_code& ec)
{
    ec.clear();
    if (plaintext.size() > tls::kMaximumPlaintextSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }

    std::vector<std::uint8_t> inner(plaintext.begin(), plaintext.end());
    inner.push_back(inner_type);
    const auto ciphertext_length = inner.size() + 16;
    std::array<std::uint8_t, 5> header{
        tls::kRecordApplicationData,
        0x03,
        0x03,
        static_cast<std::uint8_t>(ciphertext_length >> 8U),
        static_cast<std::uint8_t>(ciphertext_length),
    };
    const auto nonce = next_nonce(ec);
    if (ec)
    {
        return {};
    }
    auto ciphertext = cipher_.seal(nonce, inner, header, ec);
    if (ec)
    {
        return {};
    }

    std::vector<std::uint8_t> output(header.begin(), header.end());
    output.insert(output.end(), ciphertext.begin(), ciphertext.end());
    return output;
}

opened_record record_key::open(std::span<const std::uint8_t, 5> header, std::span<const std::uint8_t> ciphertext, boost::system::error_code& ec)
{
    ec.clear();
    if (ciphertext.size() < 17 || ciphertext.size() > tls::kMaximumCiphertextSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }
    const auto nonce = next_nonce(ec);
    if (ec)
    {
        return {};
    }
    auto plaintext = cipher_.open(nonce, ciphertext, header, ec);
    if (ec)
    {
        return {};
    }
    const auto type_position = std::find_if(plaintext.rbegin(), plaintext.rend(), [](std::uint8_t value) { return value != 0; });
    if (type_position == plaintext.rend())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return {};
    }
    const auto reverse_offset = static_cast<std::size_t>(type_position - plaintext.rbegin());
    const auto type_index = plaintext.size() - 1 - reverse_offset;
    const auto inner_type = plaintext[type_index];
    plaintext.resize(type_index);
    return {inner_type, std::move(plaintext)};
}

std::optional<handshake_secrets> derive_handshake_secrets(cipher_suite suite,
                                                          std::span<const std::uint8_t> shared_secret,
                                                          std::span<const std::uint8_t> transcript,
                                                          boost::system::error_code& ec)
{
    ec.clear();
    const auto properties = cipher_properties(suite);
    if (properties.key_length == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_not_supported);
        return std::nullopt;
    }
    const std::vector<std::uint8_t> zero(crypto::hash_size(properties.hash));
    const auto empty_hash = crypto::digest(properties.hash, {}, ec);
    if (ec)
    {
        return std::nullopt;
    }
    const auto early_secret = crypto::hkdf_extract(properties.hash, zero, zero, ec);
    if (ec)
    {
        return std::nullopt;
    }
    const auto derived = derive_secret(properties.hash, early_secret, "derived", empty_hash, ec);
    if (ec)
    {
        return std::nullopt;
    }
    const auto handshake_secret = crypto::hkdf_extract(properties.hash, derived, shared_secret, ec);
    if (ec)
    {
        return std::nullopt;
    }
    const auto transcript_hash = crypto::digest(properties.hash, transcript, ec);
    if (ec)
    {
        return std::nullopt;
    }
    auto client_secret = derive_secret(properties.hash, handshake_secret, "c hs traffic", transcript_hash, ec);
    if (ec)
    {
        return std::nullopt;
    }
    auto server_secret = derive_secret(properties.hash, handshake_secret, "s hs traffic", transcript_hash, ec);
    if (ec)
    {
        return std::nullopt;
    }
    const auto master_derived = derive_secret(properties.hash, handshake_secret, "derived", empty_hash, ec);
    if (ec)
    {
        return std::nullopt;
    }
    auto master_secret = crypto::hkdf_extract(properties.hash, master_derived, zero, ec);
    if (ec)
    {
        return std::nullopt;
    }

    record_key client_key(suite, client_secret, ec);
    if (ec)
    {
        return std::nullopt;
    }
    record_key server_key(suite, server_secret, ec);
    if (ec)
    {
        return std::nullopt;
    }

    return handshake_secrets{
        std::move(client_key),
        std::move(server_key),
        std::move(client_secret),
        std::move(server_secret),
        std::move(master_secret),
    };
}

std::optional<application_keys> derive_application_keys(cipher_suite suite,
                                                        std::span<const std::uint8_t> master_secret,
                                                        std::span<const std::uint8_t> transcript,
                                                        boost::system::error_code& ec)
{
    ec.clear();
    const auto properties = cipher_properties(suite);
    if (properties.key_length == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_not_supported);
        return std::nullopt;
    }
    const auto transcript_hash = crypto::digest(properties.hash, transcript, ec);
    if (ec)
    {
        return std::nullopt;
    }
    auto client_secret = derive_secret(properties.hash, master_secret, "c ap traffic", transcript_hash, ec);
    if (ec)
    {
        return std::nullopt;
    }
    auto server_secret = derive_secret(properties.hash, master_secret, "s ap traffic", transcript_hash, ec);
    if (ec)
    {
        return std::nullopt;
    }
    record_key client(suite, client_secret, ec);
    if (ec)
    {
        return std::nullopt;
    }
    record_key server(suite, server_secret, ec);
    if (ec)
    {
        return std::nullopt;
    }
    crypto::cleanse(client_secret);
    crypto::cleanse(server_secret);
    return application_keys{std::move(client), std::move(server)};
}

std::vector<std::uint8_t> finished_verify_data(cipher_suite suite,
                                               std::span<const std::uint8_t> traffic_secret,
                                               std::span<const std::uint8_t> transcript,
                                               boost::system::error_code& ec)
{
    ec.clear();
    const auto properties = cipher_properties(suite);
    if (properties.key_length == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_not_supported);
        return {};
    }
    constexpr std::array<std::uint8_t, 8> kLabel{'f', 'i', 'n', 'i', 's', 'h', 'e', 'd'};
    auto finished_key = hkdf_expand_label(properties.hash, traffic_secret, kLabel, {}, crypto::hash_size(properties.hash), ec);
    if (ec)
    {
        return {};
    }
    const auto transcript_hash = crypto::digest(properties.hash, transcript, ec);
    if (ec)
    {
        crypto::cleanse(finished_key);
        return {};
    }
    auto result = crypto::hmac(properties.hash, finished_key, transcript_hash, ec);
    crypto::cleanse(finished_key);
    return result;
}

}    // namespace rv::reality

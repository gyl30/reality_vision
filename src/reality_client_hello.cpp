#include "reality_client_hello.hpp"

#include "crypto.hpp"
#include "byte_order.hpp"
#include "byte_writer.hpp"
#include "tls_constants.hpp"

#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <limits>
#include <span>
#include <string_view>

namespace rv::reality
{
namespace
{

constexpr std::uint16_t kExtensionExtendedMasterSecret = 0x0017;
constexpr std::uint16_t kExtensionRenegotiationInfo = 0xff01;
constexpr std::uint16_t kExtensionSupportedGroups = 0x000a;
constexpr std::uint16_t kExtensionEcPointFormats = 0x000b;
constexpr std::uint16_t kExtensionSessionTicket = 0x0023;
constexpr std::uint16_t kExtensionAlpn = 0x0010;
constexpr std::uint16_t kExtensionStatusRequest = 0x0005;
constexpr std::uint16_t kExtensionDelegatedCredentials = 0x0022;
constexpr std::uint16_t kExtensionSignatureAlgorithms = 0x000d;
constexpr std::uint16_t kExtensionPskKeyExchangeModes = 0x002d;
constexpr std::uint16_t kExtensionRecordSizeLimit = 0x001c;
constexpr std::uint16_t kExtensionEncryptedClientHello = 0xfe0d;

constexpr std::uint16_t kNamedGroupSecp384r1 = 0x0018;
constexpr std::uint16_t kNamedGroupSecp521r1 = 0x0019;
constexpr std::uint16_t kNamedGroupFfdhe2048 = 0x0100;
constexpr std::uint16_t kNamedGroupFfdhe3072 = 0x0101;

constexpr std::uint8_t kServerNameTypeHostName = 0;
constexpr std::size_t kServerNameEntryOverhead = 3;
constexpr std::uint8_t kEchClientHelloOuter = 0;
constexpr std::uint16_t kHpkeKdfHkdfSha256 = 0x0001;
constexpr std::uint16_t kHpkeAeadAes128Gcm = 0x0001;
constexpr std::uint16_t kHpkeAeadChacha20Poly1305 = 0x0003;
constexpr std::size_t kGreaseEchPayloadSize = 239;

constexpr std::size_t kRealityAuthenticationSize = 16;
constexpr std::size_t kRealitySaltSize = 20;
constexpr std::size_t kRealityNonceSize = tls::kRandomSize - kRealitySaltSize;
static_assert(kRealityNonceSize == 12);
static_assert(kRealityAuthenticationSize + crypto::kAeadTagSize == kRealitySessionIdSize);

void append_u16_vector(std::span<const std::uint16_t> values, std::vector<std::uint8_t>& output, boost::system::error_code& ec)
{
    if (values.size() > std::numeric_limits<std::uint16_t>::max() / 2U)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    core::append_be16(output, static_cast<std::uint16_t>(values.size() * 2U));
    for (const auto value : values)
    {
        core::append_be16(output, value);
    }
}

void push_extension(std::vector<std::uint8_t>& output, std::uint16_t type, std::span<const std::uint8_t> data, boost::system::error_code& ec)
{
    if (ec)
    {
        return;
    }
    if (data.size() > std::numeric_limits<std::uint16_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    core::append_be16(output, type);
    core::append_be16(output, static_cast<std::uint16_t>(data.size()));
    output.insert(output.end(), data.begin(), data.end());
}

std::vector<std::uint8_t> server_name_extension(const std::string& server_name, boost::system::error_code& ec)
{
    if (server_name.empty() || server_name.size() > std::numeric_limits<std::uint16_t>::max() - kServerNameEntryOverhead ||
        server_name.find('\0') != std::string::npos)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    std::vector<std::uint8_t> name;
    name.push_back(kServerNameTypeHostName);
    core::append_be16(name, static_cast<std::uint16_t>(server_name.size()));
    name.insert(name.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> output;
    core::append_be16(output, static_cast<std::uint16_t>(name.size()));
    output.insert(output.end(), name.begin(), name.end());
    return output;
}

std::vector<std::uint8_t> alpn_extension()
{
    constexpr std::array<std::string_view, 2> kProtocols{"h2", "http/1.1"};
    std::vector<std::uint8_t> list;
    for (const auto protocol : kProtocols)
    {
        list.push_back(static_cast<std::uint8_t>(protocol.size()));
        list.insert(list.end(), protocol.begin(), protocol.end());
    }
    std::vector<std::uint8_t> output;
    core::append_be16(output, static_cast<std::uint16_t>(list.size()));
    output.insert(output.end(), list.begin(), list.end());
    return output;
}

std::vector<std::uint8_t> key_share_extension(const std::array<std::uint8_t, tls::kX25519KeyShareSize>& x25519_public,
                                              const std::array<std::uint8_t, crypto::kP256PublicKeySize>& p256_public)
{
    std::vector<std::uint8_t> shares;
    core::append_be16(shares, tls::kNamedGroupX25519);
    core::append_be16(shares, static_cast<std::uint16_t>(x25519_public.size()));
    shares.insert(shares.end(), x25519_public.begin(), x25519_public.end());
    core::append_be16(shares, tls::kNamedGroupSecp256r1);
    core::append_be16(shares, static_cast<std::uint16_t>(p256_public.size()));
    shares.insert(shares.end(), p256_public.begin(), p256_public.end());

    std::vector<std::uint8_t> output;
    core::append_be16(output, static_cast<std::uint16_t>(shares.size()));
    output.insert(output.end(), shares.begin(), shares.end());
    return output;
}

void push_server_name_extension(std::vector<std::uint8_t>& extensions, const std::string& server_name, boost::system::error_code& ec)
{
    if (ec)
    {
        return;
    }
    const auto data = server_name_extension(server_name, ec);
    if (ec)
    {
        return;
    }
    push_extension(extensions, tls::kExtensionServerName, data, ec);
}

void push_u16_list_extension(std::vector<std::uint8_t>& extensions,
                             const std::uint16_t type,
                             const std::span<const std::uint16_t> values,
                             boost::system::error_code& ec)
{
    if (ec)
    {
        return;
    }
    std::vector<std::uint8_t> data;
    append_u16_vector(values, data, ec);
    if (ec)
    {
        return;
    }
    push_extension(extensions, type, data, ec);
}

void push_key_share_extension(std::vector<std::uint8_t>& extensions,
                              const std::array<std::uint8_t, tls::kX25519KeyShareSize>& x25519_public,
                              boost::system::error_code& ec)
{
    if (ec)
    {
        return;
    }
    const auto p256_public = crypto::make_p256_public_key(ec);
    if (ec)
    {
        return;
    }
    const auto data = key_share_extension(x25519_public, p256_public);
    push_extension(extensions, tls::kExtensionKeyShare, data, ec);
}

std::vector<std::uint8_t> grease_ech_extension(boost::system::error_code& ec)
{
    std::array<std::uint8_t, 2> choices{};
    crypto::random_bytes(choices, ec);
    if (ec)
    {
        return {};
    }
    const std::uint16_t aead_id = (choices[0] & 1U) == 0 ? kHpkeAeadAes128Gcm : kHpkeAeadChacha20Poly1305;
    const auto encapsulated = crypto::make_x25519_key_pair();
    std::vector<std::uint8_t> payload(kGreaseEchPayloadSize);
    crypto::random_bytes(payload, ec);
    if (ec)
    {
        return {};
    }

    std::vector<std::uint8_t> output;
    output.reserve(1 + 4 + 1 + 2 + encapsulated.public_key.size() + 2 + payload.size());
    output.push_back(kEchClientHelloOuter);
    core::append_be16(output, kHpkeKdfHkdfSha256);
    core::append_be16(output, aead_id);
    output.push_back(choices[1]);
    core::append_be16(output, static_cast<std::uint16_t>(encapsulated.public_key.size()));
    output.insert(output.end(), encapsulated.public_key.begin(), encapsulated.public_key.end());
    core::append_be16(output, static_cast<std::uint16_t>(payload.size()));
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

void push_grease_ech_extension(std::vector<std::uint8_t>& extensions, boost::system::error_code& ec)
{
    if (ec)
    {
        return;
    }
    const auto data = grease_ech_extension(ec);
    if (ec)
    {
        return;
    }
    push_extension(extensions, kExtensionEncryptedClientHello, data, ec);
}

std::vector<std::uint8_t> firefox_120_extensions(const client_config& configuration,
                                                 const std::array<std::uint8_t, tls::kX25519KeyShareSize>& x25519_public,
                                                 boost::system::error_code& ec)
{
    std::vector<std::uint8_t> extensions;

    push_server_name_extension(extensions, configuration.server_name, ec);
    push_extension(extensions, kExtensionExtendedMasterSecret, {}, ec);

    constexpr std::array<std::uint8_t, 1> kRenegotiationInfo{0};
    push_extension(extensions, kExtensionRenegotiationInfo, kRenegotiationInfo, ec);

    constexpr std::array<std::uint16_t, 6> kSupportedGroups{
        tls::kNamedGroupX25519,
        tls::kNamedGroupSecp256r1,
        kNamedGroupSecp384r1,
        kNamedGroupSecp521r1,
        kNamedGroupFfdhe2048,
        kNamedGroupFfdhe3072,
    };
    push_u16_list_extension(extensions, kExtensionSupportedGroups, kSupportedGroups, ec);

    constexpr std::array<std::uint8_t, 2> kEcPointFormats{1, 0};
    push_extension(extensions, kExtensionEcPointFormats, kEcPointFormats, ec);
    push_extension(extensions, kExtensionSessionTicket, {}, ec);

    const auto alpn = alpn_extension();
    push_extension(extensions, kExtensionAlpn, alpn, ec);

    constexpr std::array<std::uint8_t, 5> kStatusRequest{1, 0, 0, 0, 0};
    push_extension(extensions, kExtensionStatusRequest, kStatusRequest, ec);

    constexpr std::array<std::uint16_t, 4> kDelegatedCredentialAlgorithms{0x0403, 0x0503, 0x0603, 0x0203};
    push_u16_list_extension(extensions, kExtensionDelegatedCredentials, kDelegatedCredentialAlgorithms, ec);

    push_key_share_extension(extensions, x25519_public, ec);

    constexpr std::array<std::uint8_t, 5> kSupportedVersions{4, 0x03, 0x04, 0x03, 0x03};
    push_extension(extensions, tls::kExtensionSupportedVersions, kSupportedVersions, ec);

    constexpr std::array<std::uint16_t, 11> kSignatureAlgorithms{
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201};
    push_u16_list_extension(extensions, kExtensionSignatureAlgorithms, kSignatureAlgorithms, ec);

    constexpr std::array<std::uint8_t, 2> kPskKeyExchangeModes{1, 1};
    push_extension(extensions, kExtensionPskKeyExchangeModes, kPskKeyExchangeModes, ec);

    constexpr std::array<std::uint8_t, 2> kRecordSizeLimit{0x40, 0x01};
    push_extension(extensions, kExtensionRecordSizeLimit, kRecordSizeLimit, ec);

    push_grease_ech_extension(extensions, ec);
    if (ec)
    {
        return {};
    }
    return extensions;
}

std::vector<std::uint8_t> build_firefox_120_handshake(const client_config& configuration,
                                                      const std::array<std::uint8_t, tls::kRandomSize>& random,
                                                      const std::array<std::uint8_t, kRealitySessionIdSize>& session_id,
                                                      const std::array<std::uint8_t, tls::kX25519KeyShareSize>& x25519_public_key,
                                                      boost::system::error_code& ec)
{
    constexpr std::array<std::uint16_t, 17> kCipherSuites{
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035};

    std::vector<std::uint8_t> body;
    body.reserve(768);
    core::append_be16(body, tls::kLegacyVersion);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(static_cast<std::uint8_t>(session_id.size()));
    body.insert(body.end(), session_id.begin(), session_id.end());
    append_u16_vector(kCipherSuites, body, ec);
    if (ec)
    {
        return {};
    }
    body.push_back(1);
    body.push_back(tls::kNullCompressionMethod);

    const auto extensions = firefox_120_extensions(configuration, x25519_public_key, ec);
    if (ec)
    {
        return {};
    }
    if (extensions.size() > std::numeric_limits<std::uint16_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }
    core::append_be16(body, static_cast<std::uint16_t>(extensions.size()));
    body.insert(body.end(), extensions.begin(), extensions.end());

    if (body.size() > tls::kMaximumHandshakeBodyLength)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }

    std::vector<std::uint8_t> handshake;
    handshake.reserve(tls::kHandshakeHeaderSize + body.size());
    handshake.push_back(tls::kHandshakeClientHello);
    core::append_be24(handshake, static_cast<std::uint32_t>(body.size()));
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

void derive_reality_auth_key(client_hello_material& material, const client_config& configuration, boost::system::error_code& ec)
{
    auto shared_secret = crypto::x25519(material.x25519_private_key, configuration.server_public_key, ec);
    if (ec)
    {
        crypto::cleanse(shared_secret);
        return;
    }

    const auto salt = std::span<const std::uint8_t>(material.client_random.data(), kRealitySaltSize);
    auto pseudorandom_key = crypto::hkdf_extract(crypto::hash_algorithm::kSha256, salt, shared_secret, ec);
    crypto::cleanse(shared_secret);
    if (ec)
    {
        crypto::cleanse(pseudorandom_key);
        return;
    }

    constexpr std::array<std::uint8_t, 7> kRealityLabel{'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
    auto auth_key = crypto::hkdf_expand(crypto::hash_algorithm::kSha256, pseudorandom_key, kRealityLabel, material.reality_auth_key.size(), ec);
    crypto::cleanse(pseudorandom_key);
    if (ec)
    {
        crypto::cleanse(auth_key);
        return;
    }

    std::copy(auth_key.begin(), auth_key.end(), material.reality_auth_key.begin());
    crypto::cleanse(auth_key);
}

std::array<std::uint8_t, kRealityAuthenticationSize> build_reality_authentication(const client_config& configuration,
                                                                                  const std::chrono::system_clock::time_point now,
                                                                                  boost::system::error_code& ec)
{
    std::array<std::uint8_t, kRealityAuthenticationSize> authentication{};
    authentication[0] = configuration.version.major;
    authentication[1] = configuration.version.minor;
    authentication[2] = configuration.version.patch;

    const auto unix_seconds = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    if (unix_seconds < 0 || static_cast<std::uint64_t>(unix_seconds) > std::numeric_limits<std::uint32_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    const auto timestamp = static_cast<std::uint32_t>(unix_seconds);
    constexpr std::size_t kTimestampOffset = 4;
    constexpr std::size_t kShortIdOffset = 8;
    core::write_be32(authentication.data() + kTimestampOffset, timestamp);
    std::copy(configuration.short_id.begin(), configuration.short_id.end(), authentication.begin() + kShortIdOffset);
    return authentication;
}

void authenticate_client_hello(client_hello_material& material,
                               const client_config& configuration,
                               const std::chrono::system_clock::time_point now,
                               boost::system::error_code& ec)
{
    derive_reality_auth_key(material, configuration, ec);
    if (ec)
    {
        return;
    }

    const auto authentication = build_reality_authentication(configuration, now, ec);
    if (ec)
    {
        return;
    }

    crypto::aead reality_aead(crypto::aead_algorithm::kAes256Gcm, material.reality_auth_key, ec);
    if (ec)
    {
        return;
    }

    const auto nonce = std::span<const std::uint8_t>(material.client_random.data() + kRealitySaltSize, kRealityNonceSize);
    const auto sealed_session_id = reality_aead.seal(nonce, authentication, material.handshake_bytes, ec);
    if (ec)
    {
        return;
    }

    std::copy(sealed_session_id.begin(), sealed_session_id.end(), material.session_id.begin());

    constexpr std::size_t kSessionIdOffset = tls::kHandshakeHeaderSize + 2 + tls::kRandomSize + 1;
    std::copy(
        material.session_id.begin(), material.session_id.end(), material.handshake_bytes.begin() + static_cast<std::ptrdiff_t>(kSessionIdOffset));
}

}    // namespace

void cleanse_client_hello_secrets(client_hello_material& material) noexcept
{
    crypto::cleanse(material.x25519_private_key);
    crypto::cleanse(material.reality_auth_key);
}

std::optional<client_hello_material> build_client_hello(const client_config& configuration,
                                                        boost::system::error_code& ec,
                                                        const std::chrono::system_clock::time_point now)
{
    if (configuration.profile != client_hello_profile::kFirefox120)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
        return std::nullopt;
    }

    client_hello_material material;
    crypto::random_bytes(material.client_random, ec);
    if (ec)
    {
        return std::nullopt;
    }

    auto key_pair = crypto::make_x25519_key_pair();
    material.x25519_private_key = key_pair.private_key;
    crypto::cleanse(key_pair.private_key);
    material.handshake_bytes = build_firefox_120_handshake(configuration, material.client_random, material.session_id, key_pair.public_key, ec);
    if (ec)
    {
        cleanse_client_hello_secrets(material);
        return std::nullopt;
    }

    authenticate_client_hello(material, configuration, now, ec);
    if (ec)
    {
        cleanse_client_hello_secrets(material);
        return std::nullopt;
    }

    return material;
}

std::vector<std::uint8_t> wrap_client_hello_record(std::span<const std::uint8_t> payload, boost::system::error_code& ec)
{
    if (payload.size() > tls::kMaximumPlaintextSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }
    constexpr std::uint16_t kClientHelloRecordVersion = 0x0301;
    std::vector<std::uint8_t> output;
    output.reserve(tls::kRecordHeaderSize + payload.size());
    output.push_back(tls::kRecordHandshake);
    core::append_be16(output, kClientHelloRecordVersion);
    core::append_be16(output, static_cast<std::uint16_t>(payload.size()));
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

}    // namespace rv::reality

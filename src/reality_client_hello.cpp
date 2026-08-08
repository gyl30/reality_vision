#include "reality_client_hello.hpp"

#include "crypto.hpp"

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

void put_u16(std::uint16_t value, std::vector<std::uint8_t>& output)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void put_u24(std::size_t value, std::vector<std::uint8_t>& output, boost::system::error_code& ec)
{
    if (value > 0x00ff'ffffU)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_u16_vector(std::span<const std::uint16_t> values, std::vector<std::uint8_t>& output, boost::system::error_code& ec)
{
    if (values.size() > std::numeric_limits<std::uint16_t>::max() / 2U)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return;
    }
    put_u16(static_cast<std::uint16_t>(values.size() * 2U), output);
    for (const auto value : values)
    {
        put_u16(value, output);
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
    put_u16(type, output);
    put_u16(static_cast<std::uint16_t>(data.size()), output);
    output.insert(output.end(), data.begin(), data.end());
}

std::vector<std::uint8_t> server_name_extension(const std::string& server_name, boost::system::error_code& ec)
{
    if (server_name.empty() || server_name.size() > std::numeric_limits<std::uint16_t>::max() - 3U || server_name.find('\0') != std::string::npos)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    std::vector<std::uint8_t> name;
    name.push_back(0);
    put_u16(static_cast<std::uint16_t>(server_name.size()), name);
    name.insert(name.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> output;
    put_u16(static_cast<std::uint16_t>(name.size()), output);
    output.insert(output.end(), name.begin(), name.end());
    return output;
}

std::vector<std::uint8_t> alpn_extension()
{
    constexpr std::array<std::string_view, 2> protocols{"h2", "http/1.1"};
    std::vector<std::uint8_t> list;
    for (const auto protocol : protocols)
    {
        list.push_back(static_cast<std::uint8_t>(protocol.size()));
        list.insert(list.end(), protocol.begin(), protocol.end());
    }
    std::vector<std::uint8_t> output;
    put_u16(static_cast<std::uint16_t>(list.size()), output);
    output.insert(output.end(), list.begin(), list.end());
    return output;
}

std::vector<std::uint8_t> key_share_extension(const std::array<std::uint8_t, 32>& x25519_public, const std::array<std::uint8_t, 65>& p256_public)
{
    std::vector<std::uint8_t> shares;
    put_u16(0x001d, shares);
    put_u16(static_cast<std::uint16_t>(x25519_public.size()), shares);
    shares.insert(shares.end(), x25519_public.begin(), x25519_public.end());
    put_u16(0x0017, shares);
    put_u16(static_cast<std::uint16_t>(p256_public.size()), shares);
    shares.insert(shares.end(), p256_public.begin(), p256_public.end());

    std::vector<std::uint8_t> output;
    put_u16(static_cast<std::uint16_t>(shares.size()), output);
    output.insert(output.end(), shares.begin(), shares.end());
    return output;
}

void push_server_name_extension(std::vector<std::uint8_t>& extensions,
                                const std::string& server_name,
                                boost::system::error_code& ec)
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
    push_extension(extensions, 0x0000, data, ec);
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
                              const std::array<std::uint8_t, 32>& x25519_public,
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
    push_extension(extensions, 0x0033, data, ec);
}

std::vector<std::uint8_t> grease_ech_extension(boost::system::error_code& ec)
{
    std::array<std::uint8_t, 2> choices{};
    crypto::random_bytes(choices, ec);
    if (ec)
    {
        return {};
    }
    const std::uint16_t aead_id = (choices[0] & 1U) == 0 ? 0x0001 : 0x0003;
    const auto encapsulated = crypto::make_x25519_key_pair();
    std::vector<std::uint8_t> payload(239);
    crypto::random_bytes(payload, ec);
    if (ec)
    {
        return {};
    }

    std::vector<std::uint8_t> output;
    output.reserve(1 + 4 + 1 + 2 + encapsulated.public_key.size() + 2 + payload.size());
    output.push_back(0x00);
    put_u16(0x0001, output);
    put_u16(aead_id, output);
    output.push_back(choices[1]);
    put_u16(static_cast<std::uint16_t>(encapsulated.public_key.size()), output);
    output.insert(output.end(), encapsulated.public_key.begin(), encapsulated.public_key.end());
    put_u16(static_cast<std::uint16_t>(payload.size()), output);
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
    push_extension(extensions, 0xfe0d, data, ec);
}

std::vector<std::uint8_t> firefox_120_extensions(const client_config& configuration,
                                                 const std::array<std::uint8_t, 32>& x25519_public,
                                                 boost::system::error_code& ec)
{
    std::vector<std::uint8_t> extensions;

    push_server_name_extension(extensions, configuration.server_name, ec);
    push_extension(extensions, 0x0017, {}, ec);

    constexpr std::array<std::uint8_t, 1> renegotiation{0};
    push_extension(extensions, 0xff01, renegotiation, ec);

    constexpr std::array<std::uint16_t, 6> groups{0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101};
    push_u16_list_extension(extensions, 0x000a, groups, ec);

    constexpr std::array<std::uint8_t, 2> point_formats{1, 0};
    push_extension(extensions, 0x000b, point_formats, ec);
    push_extension(extensions, 0x0023, {}, ec);

    const auto alpn = alpn_extension();
    push_extension(extensions, 0x0010, alpn, ec);

    constexpr std::array<std::uint8_t, 5> status_request{1, 0, 0, 0, 0};
    push_extension(extensions, 0x0005, status_request, ec);

    constexpr std::array<std::uint16_t, 4> delegated_algorithms{0x0403, 0x0503, 0x0603, 0x0203};
    push_u16_list_extension(extensions, 0x0022, delegated_algorithms, ec);

    push_key_share_extension(extensions, x25519_public, ec);

    constexpr std::array<std::uint8_t, 5> versions{4, 0x03, 0x04, 0x03, 0x03};
    push_extension(extensions, 0x002b, versions, ec);

    constexpr std::array<std::uint16_t, 11> signature_algorithms{
        0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601, 0x0203, 0x0201};
    push_u16_list_extension(extensions, 0x000d, signature_algorithms, ec);

    constexpr std::array<std::uint8_t, 2> psk_modes{1, 1};
    push_extension(extensions, 0x002d, psk_modes, ec);

    constexpr std::array<std::uint8_t, 2> record_size_limit{0x40, 0x01};
    push_extension(extensions, 0x001c, record_size_limit, ec);

    push_grease_ech_extension(extensions, ec);
    if (ec)
    {
        return {};
    }
    return extensions;
}

std::vector<std::uint8_t> build_firefox_120_handshake(const client_config& configuration,
                                                      const std::array<std::uint8_t, 32>& random,
                                                      const std::array<std::uint8_t, 32>& session_id,
                                                      const std::array<std::uint8_t, 32>& x25519_public_key,
                                                      boost::system::error_code& ec)
{
    constexpr std::array<std::uint16_t, 17> cipher_suites{
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035};

    std::vector<std::uint8_t> body;
    body.reserve(768);
    body.push_back(0x03);
    body.push_back(0x03);
    body.insert(body.end(), random.begin(), random.end());
    body.push_back(static_cast<std::uint8_t>(session_id.size()));
    body.insert(body.end(), session_id.begin(), session_id.end());
    append_u16_vector(cipher_suites, body, ec);
    if (ec)
    {
        return {};
    }
    body.push_back(1);
    body.push_back(0);

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
    put_u16(static_cast<std::uint16_t>(extensions.size()), body);
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake;
    handshake.reserve(4 + body.size());
    handshake.push_back(1);
    put_u24(body.size(), handshake, ec);
    if (ec)
    {
        return {};
    }
    handshake.insert(handshake.end(), body.begin(), body.end());
    return handshake;
}

void derive_reality_auth_key(client_hello_material& material, const client_config& configuration, boost::system::error_code& ec)
{
    auto shared_secret = crypto::x25519(material.x25519_private_key, configuration.server_public_key, ec);
    if (ec)
    {
        return;
    }

    const auto salt = std::span<const std::uint8_t>(material.client_random.data(), 20);
    auto pseudorandom_key = crypto::hkdf_extract(crypto::hash_algorithm::sha256, salt, shared_secret, ec);
    crypto::cleanse(shared_secret);
    if (ec)
    {
        return;
    }

    constexpr std::array<std::uint8_t, 7> reality_label{'R', 'E', 'A', 'L', 'I', 'T', 'Y'};
    auto auth_key = crypto::hkdf_expand(crypto::hash_algorithm::sha256, pseudorandom_key, reality_label, material.reality_auth_key.size(), ec);
    crypto::cleanse(pseudorandom_key);
    if (ec)
    {
        return;
    }

    std::copy(auth_key.begin(), auth_key.end(), material.reality_auth_key.begin());
    crypto::cleanse(auth_key);
}

std::array<std::uint8_t, 16> build_reality_authentication(const client_config& configuration,
                                                          const std::chrono::system_clock::time_point now,
                                                          boost::system::error_code& ec)
{
    std::array<std::uint8_t, 16> authentication{};
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
    authentication[4] = static_cast<std::uint8_t>(timestamp >> 24U);
    authentication[5] = static_cast<std::uint8_t>(timestamp >> 16U);
    authentication[6] = static_cast<std::uint8_t>(timestamp >> 8U);
    authentication[7] = static_cast<std::uint8_t>(timestamp);
    std::copy(configuration.short_id.begin(), configuration.short_id.end(), authentication.begin() + 8);
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

    crypto::aead reality_aead(crypto::aead_algorithm::aes_256_gcm, material.reality_auth_key, ec);
    if (ec)
    {
        return;
    }

    const auto nonce = std::span<const std::uint8_t>(material.client_random.data() + 20, 12);
    const auto sealed_session_id = reality_aead.seal(nonce, authentication, material.handshake_bytes, ec);
    if (ec)
    {
        return;
    }

    std::copy(sealed_session_id.begin(), sealed_session_id.end(), material.session_id.begin());

    constexpr std::size_t session_id_offset = 39;
    std::copy(
        material.session_id.begin(), material.session_id.end(), material.handshake_bytes.begin() + static_cast<std::ptrdiff_t>(session_id_offset));
}

}    // namespace

std::optional<client_hello_material> build_client_hello(const client_config& configuration,
                                                        boost::system::error_code& ec,
                                                        const std::chrono::system_clock::time_point now)
{
    ec.clear();
    if (configuration.profile != client_hello_profile::firefox_120)
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

    const auto key_pair = crypto::make_x25519_key_pair();
    material.x25519_private_key = key_pair.private_key;
    material.handshake_bytes = build_firefox_120_handshake(configuration, material.client_random, material.session_id, key_pair.public_key, ec);
    if (ec)
    {
        return std::nullopt;
    }

    authenticate_client_hello(material, configuration, now, ec);
    if (ec)
    {
        return std::nullopt;
    }

    return material;
}

std::vector<std::uint8_t> wrap_plain_record(std::uint8_t content_type, std::span<const std::uint8_t> payload, boost::system::error_code& ec)
{
    ec.clear();
    if (payload.size() > std::numeric_limits<std::uint16_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }
    std::vector<std::uint8_t> output;
    output.reserve(5 + payload.size());
    output.push_back(content_type);
    output.push_back(0x03);
    output.push_back(0x01);
    put_u16(static_cast<std::uint16_t>(payload.size()), output);
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

}    // namespace rv::reality

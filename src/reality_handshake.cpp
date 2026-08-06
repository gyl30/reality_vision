#include "reality_handshake.hpp"

#include "byte_queue.hpp"
#include "crypto.hpp"
#include "reality_client_hello.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <vector>

namespace rv::reality
{
namespace
{

constexpr std::uint8_t handshake_server_hello = 2;
constexpr std::uint8_t handshake_new_session_ticket = 4;
constexpr std::uint8_t handshake_encrypted_extensions = 8;
constexpr std::uint8_t handshake_certificate = 11;
constexpr std::uint8_t handshake_certificate_verify = 15;
constexpr std::uint8_t handshake_finished = 20;
constexpr std::size_t maximum_handshake_message = 1U << 20;

struct wire_record
{
    std::array<std::uint8_t, 5> header{};
    std::uint8_t type{};
    std::vector<std::uint8_t> payload;
};

struct handshake_message
{
    std::uint8_t type{};
    std::vector<std::uint8_t> raw;
};

std::span<const std::uint8_t> handshake_body(const handshake_message& message) noexcept
{
    if (message.raw.size() < 4)
    {
        return {};
    }
    return {message.raw.data() + 4, message.raw.size() - 4};
}

struct parsed_server_hello
{
    std::vector<std::uint8_t> session_id;
    cipher_suite suite{cipher_suite::unknown};
    std::array<std::uint8_t, 32> x25519_key_share{};
};

void bad_message(boost::system::error_code& ec)
{
    ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
}

bool take(
    std::span<const std::uint8_t> input,
    std::size_t& position,
    std::size_t length,
    std::span<const std::uint8_t>& output,
    boost::system::error_code& ec)
{
    if (position > input.size() || length > input.size() - position)
    {
        bad_message(ec);
        output = {};
        return false;
    }
    output = input.subspan(position, length);
    position += length;
    return true;
}

bool take_u8(
    std::span<const std::uint8_t> input,
    std::size_t& position,
    std::uint8_t& output,
    boost::system::error_code& ec)
{
    std::span<const std::uint8_t> bytes;
    if (!take(input, position, 1, bytes, ec)) return false;
    output = bytes[0];
    return true;
}

bool take_u16(
    std::span<const std::uint8_t> input,
    std::size_t& position,
    std::uint16_t& output,
    boost::system::error_code& ec)
{
    std::span<const std::uint8_t> bytes;
    if (!take(input, position, 2, bytes, ec)) return false;
    output = static_cast<std::uint16_t>(static_cast<std::uint16_t>(bytes[0]) << 8U |
                                        static_cast<std::uint16_t>(bytes[1]));
    return true;
}

bool take_u24(
    std::span<const std::uint8_t> input,
    std::size_t& position,
    std::size_t& output,
    boost::system::error_code& ec)
{
    std::span<const std::uint8_t> bytes;
    if (!take(input, position, 3, bytes, ec)) return false;
    output = static_cast<std::size_t>(bytes[0]) << 16U |
             static_cast<std::size_t>(bytes[1]) << 8U |
             static_cast<std::size_t>(bytes[2]);
    return true;
}

boost::asio::awaitable<void> read_exact(
    net::tcp_byte_stream& stream,
    std::span<std::uint8_t> output,
    boost::system::error_code& ec)
{
    std::size_t offset = 0;
    while (offset != output.size())
    {
        const auto count = co_await stream.async_read_some(output.subspan(offset), ec);
        if (ec)
        {
            co_return;
        }
        if (count == 0)
        {
            ec = boost::asio::error::eof;
            co_return;
        }
        offset += count;
    }
}

boost::asio::awaitable<wire_record> read_record(
    net::tcp_byte_stream& stream,
    boost::system::error_code& ec)
{
    wire_record record;
    co_await read_exact(stream, record.header, ec);
    if (ec) co_return record;

    record.type = record.header[0];
    const auto length = static_cast<std::size_t>(record.header[3]) << 8U |
                        static_cast<std::size_t>(record.header[4]);
    if (length > max_tls_ciphertext)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return record;
    }
    record.payload.resize(length);
    co_await read_exact(stream, record.payload, ec);
    co_return record;
}

std::optional<handshake_message> pop_handshake(
    core::byte_queue& queue,
    boost::system::error_code& ec)
{
    if (queue.size() < 4)
    {
        return std::nullopt;
    }
    const auto data = queue.data();
    const auto body_length = static_cast<std::size_t>(data[1]) << 16U |
                             static_cast<std::size_t>(data[2]) << 8U |
                             static_cast<std::size_t>(data[3]);
    if (body_length > maximum_handshake_message)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return std::nullopt;
    }
    if (queue.size() < 4 + body_length)
    {
        return std::nullopt;
    }
    auto raw = queue.take(4 + body_length);
    return handshake_message{raw[0], std::move(raw)};
}

boost::asio::awaitable<handshake_message> read_plain_handshake(
    net::tcp_byte_stream& stream,
    core::byte_queue& queue,
    boost::system::error_code& ec)
{
    for (;;)
    {
        if (auto message = pop_handshake(queue, ec))
        {
            co_return std::move(*message);
        }
        if (ec) co_return handshake_message{};

        auto record = co_await read_record(stream, ec);
        if (ec) co_return handshake_message{};
        if (record.type == tls_record_change_cipher_spec)
        {
            continue;
        }
        if (record.type != tls_record_handshake || record.header[1] != 0x03)
        {
            bad_message(ec);
            co_return handshake_message{};
        }
        if (!queue.append(record.payload, ec))
        {
            co_return handshake_message{};
        }
    }
}

boost::asio::awaitable<handshake_message> read_encrypted_handshake(
    net::tcp_byte_stream& stream,
    record_key& key,
    core::byte_queue& queue,
    boost::system::error_code& ec)
{
    for (;;)
    {
        if (auto message = pop_handshake(queue, ec))
        {
            co_return std::move(*message);
        }
        if (ec) co_return handshake_message{};

        auto record = co_await read_record(stream, ec);
        if (ec) co_return handshake_message{};
        if (record.type == tls_record_change_cipher_spec)
        {
            continue;
        }
        if (record.type != tls_record_application_data || record.header[1] != 0x03 || record.header[2] != 0x03)
        {
            bad_message(ec);
            co_return handshake_message{};
        }

        auto opened = key.open(record.header, record.payload, ec);
        if (ec) co_return handshake_message{};
        if (opened.inner_type == tls_record_alert)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::connection_aborted);
            co_return handshake_message{};
        }
        if (opened.inner_type != tls_record_handshake)
        {
            bad_message(ec);
            co_return handshake_message{};
        }
        if (!queue.append(opened.content, ec))
        {
            co_return handshake_message{};
        }
    }
}

parsed_server_hello parse_server_hello(
    const handshake_message& message,
    boost::system::error_code& ec)
{
    parsed_server_hello result;
    if (message.type != handshake_server_hello || message.raw.size() < 42)
    {
        bad_message(ec);
        return result;
    }

    constexpr std::array<std::uint8_t, 32> hello_retry_request{
        0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
        0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

    const auto body = handshake_body(message);
    std::size_t position = 0;
    std::uint16_t legacy_version = 0;
    if (!take_u16(body, position, legacy_version, ec) || legacy_version != 0x0303)
    {
        if (!ec) bad_message(ec);
        return result;
    }

    std::span<const std::uint8_t> random;
    if (!take(body, position, 32, random, ec)) return result;
    if (std::equal(random.begin(), random.end(), hello_retry_request.begin()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
        return result;
    }

    std::uint8_t session_length = 0;
    if (!take_u8(body, position, session_length, ec)) return result;
    std::span<const std::uint8_t> session;
    if (!take(body, position, session_length, session, ec)) return result;
    result.session_id.assign(session.begin(), session.end());

    std::uint16_t suite_value = 0;
    if (!take_u16(body, position, suite_value, ec)) return result;
    result.suite = parse_cipher_suite(suite_value, ec);
    if (ec) return result;

    std::uint8_t compression = 0;
    if (!take_u8(body, position, compression, ec) || compression != 0)
    {
        if (!ec) bad_message(ec);
        return result;
    }

    std::uint16_t extensions_length = 0;
    if (!take_u16(body, position, extensions_length, ec)) return result;
    std::span<const std::uint8_t> extensions;
    if (!take(body, position, extensions_length, extensions, ec) || position != body.size())
    {
        if (!ec) bad_message(ec);
        return result;
    }

    bool tls13 = false;
    bool key_share_seen = false;
    std::size_t extension_position = 0;
    while (extension_position < extensions.size())
    {
        std::uint16_t type = 0;
        std::uint16_t length = 0;
        if (!take_u16(extensions, extension_position, type, ec) ||
            !take_u16(extensions, extension_position, length, ec)) return result;
        std::span<const std::uint8_t> data;
        if (!take(extensions, extension_position, length, data, ec)) return result;

        if (type == 0x002b)
        {
            if (data.size() != 2 || data[0] != 0x03 || data[1] != 0x04)
            {
                bad_message(ec);
                return result;
            }
            tls13 = true;
        }
        else if (type == 0x0033)
        {
            std::size_t share_position = 0;
            std::uint16_t group = 0;
            std::uint16_t share_length = 0;
            if (!take_u16(data, share_position, group, ec) ||
                !take_u16(data, share_position, share_length, ec)) return result;
            std::span<const std::uint8_t> share;
            if (!take(data, share_position, share_length, share, ec)) return result;
            if (share_position != data.size() || group != 0x001d || share.size() != result.x25519_key_share.size())
            {
                bad_message(ec);
                return result;
            }
            std::copy(share.begin(), share.end(), result.x25519_key_share.begin());
            key_share_seen = true;
        }
    }

    if (!tls13 || !key_share_seen)
    {
        bad_message(ec);
    }
    return result;
}

std::vector<std::uint8_t> parse_leaf_certificate(
    const handshake_message& message,
    boost::system::error_code& ec)
{
    const auto body = handshake_body(message);
    std::size_t position = 0;
    std::uint8_t context_length = 0;
    if (!take_u8(body, position, context_length, ec)) return {};
    std::span<const std::uint8_t> context;
    if (!take(body, position, context_length, context, ec)) return {};

    std::size_t list_length = 0;
    if (!take_u24(body, position, list_length, ec)) return {};
    std::span<const std::uint8_t> list;
    if (!take(body, position, list_length, list, ec) || position != body.size())
    {
        if (!ec) bad_message(ec);
        return {};
    }

    std::size_t list_position = 0;
    std::size_t certificate_length = 0;
    if (!take_u24(list, list_position, certificate_length, ec)) return {};
    std::span<const std::uint8_t> certificate;
    if (!take(list, list_position, certificate_length, certificate, ec)) return {};
    std::uint16_t certificate_extensions_length = 0;
    if (!take_u16(list, list_position, certificate_extensions_length, ec)) return {};
    std::span<const std::uint8_t> certificate_extensions;
    if (!take(list, list_position, certificate_extensions_length, certificate_extensions, ec)) return {};
    if (certificate.empty())
    {
        bad_message(ec);
        return {};
    }
    return {certificate.begin(), certificate.end()};
}

bool validate_encrypted_extensions(
    const handshake_message& message,
    boost::system::error_code& ec)
{
    const auto body = handshake_body(message);
    std::size_t position = 0;
    std::uint16_t length = 0;
    if (!take_u16(body, position, length, ec)) return false;
    std::span<const std::uint8_t> extensions;
    if (!take(body, position, length, extensions, ec)) return false;
    if (position != body.size())
    {
        bad_message(ec);
        return false;
    }
    return true;
}

bool verify_certificate_verify(
    const handshake_message& message,
    std::span<const std::uint8_t, 32> public_key,
    cipher_suite suite,
    std::span<const std::uint8_t> transcript,
    boost::system::error_code& ec)
{
    const auto body = handshake_body(message);
    std::size_t position = 0;
    std::uint16_t algorithm = 0;
    std::uint16_t signature_length = 0;
    if (!take_u16(body, position, algorithm, ec) ||
        !take_u16(body, position, signature_length, ec)) return false;
    std::span<const std::uint8_t> signature;
    if (!take(body, position, signature_length, signature, ec)) return false;
    if (position != body.size() || algorithm != 0x0807)
    {
        bad_message(ec);
        return false;
    }

    std::vector<std::uint8_t> signed_message(64, 0x20);
    constexpr std::string_view context = "TLS 1.3, server CertificateVerify";
    signed_message.insert(signed_message.end(), context.begin(), context.end());
    signed_message.push_back(0);
    const auto transcript_hash = crypto::digest(cipher_properties(suite).hash, transcript, ec);
    if (ec) return false;
    signed_message.insert(signed_message.end(), transcript_hash.begin(), transcript_hash.end());
    return crypto::verify_ed25519(public_key, signed_message, signature, ec);
}

std::vector<std::uint8_t> make_handshake_message(
    std::uint8_t type,
    std::span<const std::uint8_t> body,
    boost::system::error_code& ec)
{
    if (body.size() > 0x00ff'ffffU)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }
    std::vector<std::uint8_t> output;
    output.reserve(4 + body.size());
    output.push_back(type);
    output.push_back(static_cast<std::uint8_t>(body.size() >> 16U));
    output.push_back(static_cast<std::uint8_t>(body.size() >> 8U));
    output.push_back(static_cast<std::uint8_t>(body.size()));
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

} // namespace

boost::asio::awaitable<std::optional<handshake_result>> perform_client_handshake(
    net::tcp_byte_stream& stream,
    const client_config& config,
    const std::string& log,
    boost::system::error_code& ec)
{
    ec.clear();
    auto hello = build_client_hello(config, ec);
    if (ec || !hello) co_return std::nullopt;

    auto transcript = hello->handshake;
    const auto hello_record = wrap_plain_record(tls_record_handshake, hello->handshake, ec);
    if (ec) co_return std::nullopt;
    co_await stream.async_write_all(hello_record, ec);
    if (ec) co_return std::nullopt;
    spdlog::info("[{}] reality client hello sent firefox 120 profile", log);

    core::byte_queue plain_handshake(maximum_handshake_message);
    auto server_hello_message = co_await read_plain_handshake(stream, plain_handshake, ec);
    if (ec) co_return std::nullopt;
    const auto server_hello = parse_server_hello(server_hello_message, ec);
    if (ec) co_return std::nullopt;
    if (!crypto::constant_time_equal(server_hello.session_id, hello->session_id))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        spdlog::error("[{}] REALITY server did not echo the authenticated session ID", log);
        co_return std::nullopt;
    }
    transcript.insert(transcript.end(), server_hello_message.raw.begin(), server_hello_message.raw.end());

    auto shared_secret = crypto::x25519(hello->x25519_private_key, server_hello.x25519_key_share, ec);
    crypto::cleanse(hello->x25519_private_key);
    if (ec) co_return std::nullopt;
    auto handshake = derive_handshake_secrets(server_hello.suite, shared_secret, transcript, ec);
    crypto::cleanse(shared_secret);
    if (ec || !handshake) co_return std::nullopt;

    core::byte_queue encrypted_handshake(maximum_handshake_message);
    enum class phase { encrypted_extensions, certificate, certificate_verify, finished };
    auto current_phase = phase::encrypted_extensions;
    std::array<std::uint8_t, 32> certificate_public_key{};

    for (;;)
    {
        auto message = co_await read_encrypted_handshake(stream, handshake->server_key, encrypted_handshake, ec);
        if (ec) co_return std::nullopt;

        if (current_phase == phase::encrypted_extensions)
        {
            if (message.type != handshake_encrypted_extensions || !validate_encrypted_extensions(message, ec))
            {
                if (!ec) bad_message(ec);
                co_return std::nullopt;
            }
            transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
            current_phase = phase::certificate;
            continue;
        }

        if (current_phase == phase::certificate)
        {
            if (message.type != handshake_certificate)
            {
                bad_message(ec);
                co_return std::nullopt;
            }
            const auto certificate_der = parse_leaf_certificate(message, ec);
            if (ec) co_return std::nullopt;
            const auto certificate = crypto::parse_reality_certificate(certificate_der, ec);
            if (ec) co_return std::nullopt;
            const auto expected_signature = crypto::hmac(
                crypto::hash_algorithm::sha512,
                hello->reality_auth_key,
                certificate.ed25519_public_key,
                ec);
            if (ec) co_return std::nullopt;
            if (!crypto::constant_time_equal(expected_signature, certificate.outer_signature))
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
                co_return std::nullopt;
            }
            certificate_public_key = certificate.ed25519_public_key;
            transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
            current_phase = phase::certificate_verify;
            continue;
        }

        if (current_phase == phase::certificate_verify)
        {
            if (message.type != handshake_certificate_verify ||
                !verify_certificate_verify(message, certificate_public_key, server_hello.suite, transcript, ec))
            {
                if (!ec) ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
                co_return std::nullopt;
            }
            transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
            current_phase = phase::finished;
            continue;
        }

        if (message.type == handshake_new_session_ticket)
        {
            continue;
        }
        if (message.type != handshake_finished)
        {
            bad_message(ec);
            co_return std::nullopt;
        }
        const auto expected = finished_verify_data(server_hello.suite, handshake->server_secret, transcript, ec);
        if (ec) co_return std::nullopt;
        if (!crypto::constant_time_equal(expected, handshake_body(message)))
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
            co_return std::nullopt;
        }
        transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
        break;
    }

    auto application = derive_application_keys(server_hello.suite, handshake->master_secret, transcript, ec);
    if (ec || !application) co_return std::nullopt;
    const auto client_verify_data = finished_verify_data(server_hello.suite, handshake->client_secret, transcript, ec);
    if (ec) co_return std::nullopt;
    const auto client_finished = make_handshake_message(handshake_finished, client_verify_data, ec);
    if (ec) co_return std::nullopt;
    const auto client_finished_record = handshake->client_key.seal(tls_record_handshake, client_finished, ec);
    if (ec) co_return std::nullopt;
    co_await stream.async_write_all(client_finished_record, ec);
    if (ec) co_return std::nullopt;

    crypto::cleanse(handshake->client_secret);
    crypto::cleanse(handshake->server_secret);
    crypto::cleanse(handshake->master_secret);
    crypto::cleanse(hello->reality_auth_key);
    spdlog::info("[{}] reality tls 1.3 handshake completed", log);
    co_return handshake_result{std::move(application->server), std::move(application->client)};
}

} // namespace rv::reality

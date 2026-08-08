#include "reality_handshake.hpp"

#include "byte_order.hpp"
#include "byte_queue.hpp"
#include "byte_reader.hpp"
#include "crypto.hpp"
#include "reality_client_hello.hpp"
#include "tls_constants.hpp"

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

constexpr std::uint16_t kExtensionKeyShare = 0x0033;
constexpr std::uint16_t kNamedGroupX25519 = 0x001d;
constexpr std::uint16_t kSignatureSchemeEd25519 = 0x0807;
constexpr std::array<std::uint8_t, 32> kHelloRetryRequestRandom{
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c};

struct tls_record
{
    std::array<std::uint8_t, tls::kRecordHeaderSize> header{};
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
    if (message.raw.size() < tls::kHandshakeHeaderSize)
    {
        return {};
    }
    return {message.raw.data() + tls::kHandshakeHeaderSize, message.raw.size() - tls::kHandshakeHeaderSize};
}

struct parsed_server_hello
{
    std::vector<std::uint8_t> session_id;
    cipher_suite suite{cipher_suite::kUnknown};
    std::array<std::uint8_t, 32> x25519_key_share{};
};

void set_bad_message_error(boost::system::error_code& ec) { ec = boost::system::errc::make_error_code(boost::system::errc::bad_message); }

boost::asio::awaitable<void> read_exact(net::tcp_byte_stream& stream, std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    std::size_t offset = 0;
    while (offset != output.size())
    {
        const auto count = co_await stream.read(output.subspan(offset), ec);
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

boost::asio::awaitable<tls_record> read_tls_record(net::tcp_byte_stream& stream, boost::system::error_code& ec)
{
    tls_record record;
    co_await read_exact(stream, record.header, ec);
    if (ec)
    {
        co_return record;
    }

    record.type = record.header[0];
    const auto length = static_cast<std::size_t>(core::read_be16(record.header.data() + 3));
    if (length > tls::kMaximumCiphertextSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return record;
    }
    record.payload.resize(length);
    co_await read_exact(stream, record.payload, ec);
    co_return record;
}

std::optional<handshake_message> pop_handshake_message(core::byte_queue& queue, boost::system::error_code& ec)
{
    if (queue.size() < 4)
    {
        return std::nullopt;
    }
    const auto data = queue.data();
    const auto body_length = static_cast<std::size_t>(core::read_be24(data.data() + 1));
    if (body_length > tls::kMaximumHandshakeMessageSize)
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

boost::asio::awaitable<handshake_message> read_plain_handshake_message(net::tcp_byte_stream& stream,
                                                                       core::byte_queue& queue,
                                                                       boost::system::error_code& ec)
{
    for (;;)
    {
        if (auto message = pop_handshake_message(queue, ec))
        {
            co_return std::move(*message);
        }
        if (ec)
        {
            co_return handshake_message{};
        }

        auto record = co_await read_tls_record(stream, ec);
        if (ec)
        {
            co_return handshake_message{};
        }
        if (record.type == tls::kRecordChangeCipherSpec)
        {
            continue;
        }
        if (record.type != tls::kRecordHandshake || record.header[1] != 0x03)
        {
            set_bad_message_error(ec);
            co_return handshake_message{};
        }
        queue.append(record.payload, ec);
        if (ec)
        {
            co_return handshake_message{};
        }
    }
}

boost::asio::awaitable<handshake_message> read_encrypted_handshake_message(net::tcp_byte_stream& stream,
                                                                           record_key& key,
                                                                           core::byte_queue& queue,
                                                                           boost::system::error_code& ec)
{
    for (;;)
    {
        if (auto message = pop_handshake_message(queue, ec))
        {
            co_return std::move(*message);
        }
        if (ec)
        {
            co_return handshake_message{};
        }

        auto record = co_await read_tls_record(stream, ec);
        if (ec)
        {
            co_return handshake_message{};
        }
        if (record.type == tls::kRecordChangeCipherSpec)
        {
            continue;
        }
        if (record.type != tls::kRecordApplicationData || record.header[1] != 0x03 || record.header[2] != 0x03)
        {
            set_bad_message_error(ec);
            co_return handshake_message{};
        }

        auto opened = key.open(record.header, record.payload, ec);
        if (ec)
        {
            co_return handshake_message{};
        }
        if (opened.inner_type == tls::kRecordAlert)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::connection_aborted);
            co_return handshake_message{};
        }
        if (opened.inner_type != tls::kRecordHandshake)
        {
            set_bad_message_error(ec);
            co_return handshake_message{};
        }
        queue.append(opened.content, ec);
        if (ec)
        {
            co_return handshake_message{};
        }
    }
}

void parse_server_key_share(const std::span<const std::uint8_t> extension_data, parsed_server_hello& server_hello, boost::system::error_code& ec)
{
    core::byte_reader reader(extension_data);
    std::uint16_t group = 0;
    std::uint16_t share_length = 0;
    if (!reader.read_u16(group) || !reader.read_u16(share_length))
    {
        set_bad_message_error(ec);
        return;
    }

    const auto share = reader.read_bytes(share_length);
    if (!share || !reader.empty() || group != kNamedGroupX25519 || share->size() != server_hello.x25519_key_share.size())
    {
        set_bad_message_error(ec);
        return;
    }

    std::copy(share->begin(), share->end(), server_hello.x25519_key_share.begin());
}

void parse_server_hello_extensions(const std::span<const std::uint8_t> extensions,
                                   parsed_server_hello& server_hello,
                                   boost::system::error_code& ec)
{
    bool tls13_seen = false;
    bool key_share_seen = false;
    core::byte_reader reader(extensions);

    while (!reader.empty())
    {
        std::uint16_t type = 0;
        std::uint16_t length = 0;
        if (!reader.read_u16(type) || !reader.read_u16(length))
        {
            set_bad_message_error(ec);
            return;
        }

        const auto extension_data = reader.read_bytes(length);
        if (!extension_data)
        {
            set_bad_message_error(ec);
            return;
        }

        if (type == tls::kExtensionSupportedVersions)
        {
            if (extension_data->size() != 2 || core::read_be16(extension_data->data()) != tls::kTls13Version)
            {
                set_bad_message_error(ec);
                return;
            }
            tls13_seen = true;
            continue;
        }

        if (type == kExtensionKeyShare)
        {
            parse_server_key_share(*extension_data, server_hello, ec);
            if (ec)
            {
                return;
            }
            key_share_seen = true;
        }
    }

    if (!tls13_seen || !key_share_seen)
    {
        set_bad_message_error(ec);
    }
}

parsed_server_hello parse_server_hello(const handshake_message& message, boost::system::error_code& ec)
{
    parsed_server_hello result;
    if (message.type != tls::kHandshakeServerHello)
    {
        set_bad_message_error(ec);
        return result;
    }


    core::byte_reader reader(handshake_body(message));
    std::uint16_t legacy_version = 0;
    if (!reader.read_u16(legacy_version) || legacy_version != tls::kLegacyVersion)
    {
        set_bad_message_error(ec);
        return result;
    }

    const auto random = reader.read_bytes(32);
    if (!random)
    {
        set_bad_message_error(ec);
        return result;
    }
    if (std::equal(random->begin(), random->end(), kHelloRetryRequestRandom.begin()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
        return result;
    }

    std::uint8_t session_length = 0;
    if (!reader.read_u8(session_length))
    {
        set_bad_message_error(ec);
        return result;
    }
    const auto session = reader.read_bytes(session_length);
    if (!session)
    {
        set_bad_message_error(ec);
        return result;
    }
    result.session_id.assign(session->begin(), session->end());

    std::uint16_t suite_value = 0;
    if (!reader.read_u16(suite_value))
    {
        set_bad_message_error(ec);
        return result;
    }
    result.suite = parse_cipher_suite(suite_value, ec);
    if (ec)
    {
        return result;
    }

    std::uint8_t compression = 0;
    if (!reader.read_u8(compression) || compression != 0)
    {
        set_bad_message_error(ec);
        return result;
    }

    std::uint16_t extensions_length = 0;
    if (!reader.read_u16(extensions_length))
    {
        set_bad_message_error(ec);
        return result;
    }
    const auto extensions = reader.read_bytes(extensions_length);
    if (!extensions || !reader.empty())
    {
        set_bad_message_error(ec);
        return result;
    }

    parse_server_hello_extensions(*extensions, result, ec);
    return result;
}

std::vector<std::uint8_t> parse_leaf_certificate(const handshake_message& message, boost::system::error_code& ec)
{
    core::byte_reader reader(handshake_body(message));
    std::uint8_t context_length = 0;
    if (!reader.read_u8(context_length))
    {
        set_bad_message_error(ec);
        return {};
    }
    if (!reader.skip(context_length))
    {
        set_bad_message_error(ec);
        return {};
    }

    std::uint32_t list_length = 0;
    if (!reader.read_u24(list_length))
    {
        set_bad_message_error(ec);
        return {};
    }
    const auto list = reader.read_bytes(list_length);
    if (!list || !reader.empty())
    {
        set_bad_message_error(ec);
        return {};
    }

    core::byte_reader list_reader(*list);
    std::uint32_t certificate_length = 0;
    if (!list_reader.read_u24(certificate_length))
    {
        set_bad_message_error(ec);
        return {};
    }
    const auto certificate = list_reader.read_bytes(certificate_length);
    if (!certificate)
    {
        set_bad_message_error(ec);
        return {};
    }

    std::uint16_t certificate_extensions_length = 0;
    if (!list_reader.read_u16(certificate_extensions_length))
    {
        set_bad_message_error(ec);
        return {};
    }
    if (!list_reader.skip(certificate_extensions_length))
    {
        set_bad_message_error(ec);
        return {};
    }

    if (certificate->empty())
    {
        set_bad_message_error(ec);
        return {};
    }

    return {certificate->begin(), certificate->end()};
}

void validate_encrypted_extensions(const handshake_message& message, boost::system::error_code& ec)
{
    core::byte_reader reader(handshake_body(message));
    std::uint16_t length = 0;
    if (!reader.read_u16(length))
    {
        set_bad_message_error(ec);
        return;
    }
    if (!reader.skip(length) || !reader.empty())
    {
        set_bad_message_error(ec);
    }
}

void verify_certificate_verify(const handshake_message& message,
                               std::span<const std::uint8_t, 32> public_key,
                               const cipher_suite suite,
                               std::span<const std::uint8_t> transcript,
                               boost::system::error_code& ec)
{
    core::byte_reader reader(handshake_body(message));
    std::uint16_t algorithm = 0;
    std::uint16_t signature_length = 0;
    if (!reader.read_u16(algorithm) || !reader.read_u16(signature_length))
    {
        set_bad_message_error(ec);
        return;
    }
    const auto signature = reader.read_bytes(signature_length);
    if (!signature || !reader.empty() || algorithm != kSignatureSchemeEd25519)
    {
        set_bad_message_error(ec);
        return;
    }

    std::vector<std::uint8_t> signed_message(64, 0x20);
    constexpr std::string_view kContext = "TLS 1.3, server CertificateVerify";
    signed_message.insert(signed_message.end(), kContext.begin(), kContext.end());
    signed_message.push_back(0);

    const auto transcript_hash = crypto::digest(cipher_properties(suite).hash, transcript, ec);
    if (ec)
    {
        return;
    }
    signed_message.insert(signed_message.end(), transcript_hash.begin(), transcript_hash.end());
    crypto::verify_ed25519(public_key, signed_message, *signature, ec);
}

std::vector<std::uint8_t> make_handshake_message(std::uint8_t type, std::span<const std::uint8_t> body, boost::system::error_code& ec)
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

void accept_encrypted_extensions(const handshake_message& message, std::vector<std::uint8_t>& transcript, boost::system::error_code& ec)
{
    if (message.type != tls::kHandshakeEncryptedExtensions)
    {
        set_bad_message_error(ec);
        return;
    }

    validate_encrypted_extensions(message, ec);
    if (ec)
    {
        return;
    }
    transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
}

void accept_server_certificate(const handshake_message& message,
                               const client_hello_material& client_hello,
                               std::array<std::uint8_t, 32>& certificate_public_key,
                               std::vector<std::uint8_t>& transcript,
                               boost::system::error_code& ec)
{
    if (message.type != tls::kHandshakeCertificate)
    {
        set_bad_message_error(ec);
        return;
    }

    const auto certificate_der = parse_leaf_certificate(message, ec);
    if (ec)
    {
        return;
    }

    const auto certificate = crypto::parse_reality_certificate(certificate_der, ec);
    if (ec)
    {
        return;
    }

    const auto expected_signature = crypto::hmac(crypto::hash_algorithm::kSha512, client_hello.reality_auth_key, certificate.ed25519_public_key, ec);
    if (ec)
    {
        return;
    }

    if (!crypto::constant_time_equal(expected_signature, certificate.outer_signature))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }

    certificate_public_key = certificate.ed25519_public_key;
    transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
}

void accept_certificate_verify(const handshake_message& message,
                               std::span<const std::uint8_t, 32> certificate_public_key,
                               const cipher_suite suite,
                               std::vector<std::uint8_t>& transcript,
                               boost::system::error_code& ec)
{
    if (message.type != tls::kHandshakeCertificateVerify)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }

    verify_certificate_verify(message, certificate_public_key, suite, transcript, ec);
    if (ec)
    {
        return;
    }
    transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
}

void accept_server_finished(const handshake_message& message,
                            const parsed_server_hello& server_hello,
                            const handshake_secrets& secrets,
                            std::vector<std::uint8_t>& transcript,
                            boost::system::error_code& ec)
{
    if (message.type != tls::kHandshakeFinished)
    {
        set_bad_message_error(ec);
        return;
    }

    const auto expected_verify_data = finished_verify_data(server_hello.suite, secrets.server_secret, transcript, ec);
    if (ec)
    {
        return;
    }

    if (!crypto::constant_time_equal(expected_verify_data, handshake_body(message)))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return;
    }

    transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
}

boost::asio::awaitable<void> read_server_handshake_flight(net::tcp_byte_stream& tcp,
                                                          const client_hello_material& client_hello,
                                                          const parsed_server_hello& server_hello,
                                                          handshake_secrets& secrets,
                                                          std::vector<std::uint8_t>& transcript,
                                                          boost::system::error_code& ec)
{
    core::byte_queue encrypted_handshake(tls::kMaximumHandshakeMessageSize);
    std::array<std::uint8_t, 32> certificate_public_key{};

    auto message = co_await read_encrypted_handshake_message(tcp, secrets.server_key, encrypted_handshake, ec);
    if (ec)
    {
        co_return;
    }
    accept_encrypted_extensions(message, transcript, ec);
    if (ec)
    {
        co_return;
    }

    message = co_await read_encrypted_handshake_message(tcp, secrets.server_key, encrypted_handshake, ec);
    if (ec)
    {
        co_return;
    }
    accept_server_certificate(message, client_hello, certificate_public_key, transcript, ec);
    if (ec)
    {
        co_return;
    }

    message = co_await read_encrypted_handshake_message(tcp, secrets.server_key, encrypted_handshake, ec);
    if (ec)
    {
        co_return;
    }
    accept_certificate_verify(message, certificate_public_key, server_hello.suite, transcript, ec);
    if (ec)
    {
        co_return;
    }

    for (;;)
    {
        message = co_await read_encrypted_handshake_message(tcp, secrets.server_key, encrypted_handshake, ec);
        if (ec)
        {
            co_return;
        }
        if (message.type == tls::kHandshakeNewSessionTicket)
        {
            continue;
        }

        accept_server_finished(message, server_hello, secrets, transcript, ec);
        co_return;
    }
}

boost::asio::awaitable<std::optional<client_hello_material>> send_client_hello(net::tcp_byte_stream& tcp,
                                                                               const client_config& configuration,
                                                                               std::vector<std::uint8_t>& transcript,
                                                                               const std::string& session_id,
                                                                               boost::system::error_code& ec)
{
    auto client_hello = build_client_hello(configuration, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    transcript = client_hello->handshake_bytes;
    const auto client_hello_record = wrap_plain_record(tls::kRecordHandshake, client_hello->handshake_bytes, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_await tcp.write(client_hello_record, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    spdlog::info("{} reality client hello sent firefox 120 profile", session_id);
    co_return client_hello;
}

boost::asio::awaitable<std::optional<parsed_server_hello>> receive_server_hello(net::tcp_byte_stream& tcp,
                                                                                const client_hello_material& client_hello,
                                                                                std::vector<std::uint8_t>& transcript,
                                                                                const std::string& session_id,
                                                                                boost::system::error_code& ec)
{
    core::byte_queue plain_handshake(tls::kMaximumHandshakeMessageSize);
    auto message = co_await read_plain_handshake_message(tcp, plain_handshake, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    auto server_hello = parse_server_hello(message, ec);
    if (ec)
    {
        co_return std::nullopt;
    }
    if (!crypto::constant_time_equal(server_hello.session_id, client_hello.session_id))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        spdlog::error("{} reality server did not echo the authenticated session id", session_id);
        co_return std::nullopt;
    }

    transcript.insert(transcript.end(), message.raw.begin(), message.raw.end());
    co_return server_hello;
}

std::optional<handshake_secrets> derive_client_handshake_secrets(client_hello_material& client_hello,
                                                                 const parsed_server_hello& server_hello,
                                                                 const std::span<const std::uint8_t> transcript,
                                                                 boost::system::error_code& ec)
{
    auto shared_secret = crypto::x25519(client_hello.x25519_private_key, server_hello.x25519_key_share, ec);
    crypto::cleanse(client_hello.x25519_private_key);
    if (ec)
    {
        return std::nullopt;
    }

    auto secrets = derive_handshake_secrets(server_hello.suite, shared_secret, transcript, ec);
    crypto::cleanse(shared_secret);
    return secrets;
}

boost::asio::awaitable<void> send_client_finished(net::tcp_byte_stream& tcp,
                                                  const cipher_suite suite,
                                                  handshake_secrets& secrets,
                                                  std::span<const std::uint8_t> transcript,
                                                  boost::system::error_code& ec)
{
    const auto verify_data = finished_verify_data(suite, secrets.client_secret, transcript, ec);
    if (ec)
    {
        co_return;
    }
    const auto finished_message = make_handshake_message(tls::kHandshakeFinished, verify_data, ec);
    if (ec)
    {
        co_return;
    }
    const auto finished_record = secrets.client_key.seal(tls::kRecordHandshake, finished_message, ec);
    if (ec)
    {
        co_return;
    }
    co_await tcp.write(finished_record, ec);
}

}    // namespace

boost::asio::awaitable<std::optional<handshake_result>> perform_client_handshake(net::tcp_byte_stream& tcp,
                                                                                 const client_config& configuration,
                                                                                 const std::string& session_id,
                                                                                 boost::system::error_code& ec)
{
    ec.clear();
    std::vector<std::uint8_t> transcript;

    auto client_hello = co_await send_client_hello(tcp, configuration, transcript, session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    auto server_hello = co_await receive_server_hello(tcp, *client_hello, transcript, session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    auto handshake_secrets = derive_client_handshake_secrets(*client_hello, *server_hello, transcript, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_await read_server_handshake_flight(tcp, *client_hello, *server_hello, *handshake_secrets, transcript, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    auto application_keys = derive_application_keys(server_hello->suite, handshake_secrets->master_secret, transcript, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_await send_client_finished(tcp, server_hello->suite, *handshake_secrets, transcript, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    crypto::cleanse(handshake_secrets->client_secret);
    crypto::cleanse(handshake_secrets->server_secret);
    crypto::cleanse(handshake_secrets->master_secret);
    crypto::cleanse(client_hello->reality_auth_key);

    spdlog::info("{} reality tls 1.3 handshake completed", session_id);
    co_return handshake_result{
        .receive_key = std::move(application_keys->server_key),
        .send_key = std::move(application_keys->client_key),
    };
}

}    // namespace rv::reality

#include "protocol_tests.hpp"

#include "network_address.hpp"

#include "base64.hpp"
#include "byte_order.hpp"
#include "byte_queue.hpp"
#include "byte_reader.hpp"
#include "byte_writer.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "hex.hpp"
#include "reality_client_hello.hpp"
#include "reality_record.hpp"
#include "socks5_protocol.hpp"
#include "sniffer.hpp"
#include "tls_constants.hpp"
#include "vision_codec.hpp"
#include "vless_header.hpp"

#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <exception>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace rv::testing
{
namespace
{

class test_failure final : public std::runtime_error
{
   public:
    using std::runtime_error::runtime_error;
};

void expect(bool condition, std::string_view message)
{
    if (!condition)
    {
        throw test_failure(std::string(message));
    }
}

void expect_error(const boost::system::error_code& ec, boost::system::errc::errc_t expected, std::string_view message)
{
    expect(ec == boost::system::errc::make_error_code(expected), message);
}

std::span<const std::uint8_t> test_subspan(const std::span<const std::uint8_t> input,
                                           const std::size_t offset,
                                           const std::size_t size,
                                           const std::string_view message)
{
    expect(offset <= input.size() && size <= input.size() - offset, message);
    return input.subspan(offset, size);
}

std::uint16_t read_test_u16(const std::span<const std::uint8_t> input, const std::size_t offset, const std::string_view message)
{
    const auto bytes = test_subspan(input, offset, 2, message);
    return rv::core::read_be16(bytes.data());
}

std::size_t read_test_u24(const std::span<const std::uint8_t> input, const std::size_t offset, const std::string_view message)
{
    const auto bytes = test_subspan(input, offset, 3, message);
    return static_cast<std::size_t>(rv::core::read_be24(bytes.data()));
}

template <std::size_t size>
void expect_bytes(const std::span<const std::uint8_t> actual, const std::array<std::uint8_t, size>& expected, const std::string_view message)
{
    expect(actual.size() == expected.size() && std::equal(actual.begin(), actual.end(), expected.begin()), message);
}

rv::app::config parse_short_id_test_config(const std::string& short_id)
{
    std::vector<std::string> arguments{
        "reality_vision",
        "--server",
        "127.0.0.1",
        "--port",
        "8443",
        "--server_name",
        "apple.com",
        "--server_public_key",
        "uL4rG3uX_6B359RLXYFNTmSWnrBSLVv1PIG6NUWjMVk",
        "--short_id",
        short_id,
        "--uuid",
        "b831381d-6324-4d53-ad4f-8cda48b30811",
        "--socks_port",
        "1080",
    };
    std::vector<char*> argv;
    argv.reserve(arguments.size());
    for (auto& argument : arguments)
    {
        argv.push_back(argument.data());
    }

    const auto configuration = rv::app::parse_config(static_cast<int>(argv.size()), argv.data());
    expect(configuration.has_value(), "short id configuration parse failed");
    return *configuration;
}

void test_byte_writer()
{
    std::vector<std::uint8_t> output;
    core::append_be16(output, 0x1234);
    core::append_be24(output, 0x0056789a);

    constexpr std::array<std::uint8_t, 5> kExpected{0x12, 0x34, 0x56, 0x78, 0x9a};
    expect_bytes(output, kExpected, "byte writer output mismatch");

    std::array<std::uint8_t, 9> fixed{};
    core::write_be16(fixed.data(), 0x1234);
    core::write_be24(fixed.data() + 2, 0x0056789a);
    core::write_be32(fixed.data() + 5, 0xbcdef012);
    constexpr std::array<std::uint8_t, 9> kExpectedFixed{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x12};
    expect(fixed == kExpectedFixed, "byte order writer output mismatch");
}

void test_network_address()
{
    expect(rv::net::format_address_port(rv::net::ipv4_address{{127, 0, 0, 1}}, 443) == "127.0.0.1:443", "IPv4 address format mismatch");
    expect(rv::net::format_address_port(rv::net::domain_address{"example.com"}, 8443) == "example.com:8443", "domain address format mismatch");

    rv::net::ipv6_address ipv6{};
    ipv6.bytes[15] = 1;
    expect(rv::net::format_address_port(ipv6, 443) == "[::1]:443", "IPv6 address format mismatch");
}

void test_short_id_config()
{
    const auto short_id = parse_short_id_test_config("01234567");
    constexpr std::array<std::uint8_t, 8> kExpectedShortId{0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00};
    expect(short_id.reality_short_id == kExpectedShortId, "short id zero padding mismatch");

    const auto full_short_id = parse_short_id_test_config("0123456789abcdef");
    constexpr std::array<std::uint8_t, 8> kExpectedFullShortId{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    expect(full_short_id.reality_short_id == kExpectedFullShortId, "full short id mismatch");

    const auto empty_short_id = parse_short_id_test_config("");
    expect(empty_short_id.reality_short_id == std::array<std::uint8_t, 8>{}, "empty short id mismatch");
}

void test_text_codecs()
{
    expect(rv::core::decode_base64_url("AAEC_w") == std::vector<std::uint8_t>({0x00, 0x01, 0x02, 0xff}), "Base64URL decode mismatch");
    expect(rv::core::decode_base64_url("TQ") == std::vector<std::uint8_t>({'M'}), "Base64URL short decode mismatch");
    expect(rv::core::decode_base64_url("A").empty(), "Base64URL accepted invalid length");
    expect(rv::core::decode_base64_url("AA+").empty(), "Base64URL accepted invalid alphabet");

    expect(rv::core::decode_hex("00abFF") == std::vector<std::uint8_t>({0x00, 0xab, 0xff}), "Hex decode mismatch");
    expect(rv::core::decode_hex("abc").empty(), "Hex accepted odd input");
    expect(rv::core::decode_hex("0g").empty(), "Hex accepted invalid digit");
}

void test_byte_queue()
{
    rv::core::byte_queue queue(8);
    boost::system::error_code ec;
    constexpr std::array<std::uint8_t, 5> kFirst{1, 2, 3, 4, 5};
    queue.append(kFirst, ec);
    expect(!ec, "byte_queue append failed");
    std::array<std::uint8_t, 2> prefix{};
    expect(queue.copy_to(prefix) == 2 && prefix == std::array<std::uint8_t, 2>{1, 2}, "byte_queue prefix mismatch");
    constexpr std::array<std::uint8_t, 6> kOversized{6, 7, 8, 9, 10, 11};
    queue.append(kOversized, ec);
    expect(ec == boost::system::errc::make_error_code(boost::system::errc::message_size), "byte_queue accepted oversized append");
    expect_error(ec, boost::system::errc::message_size, "byte_queue returned wrong error");
}

void test_byte_reader()
{
    constexpr std::array<std::uint8_t, 11> kInput{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 1, 2, 3, 4};
    rv::core::byte_reader reader(kInput);

    std::uint8_t value8 = 0;
    std::uint16_t value16 = 0;
    std::uint32_t value24 = 0;
    expect(reader.read_u8(value8) && value8 == 0x12, "byte_reader u8 mismatch");
    expect(reader.read_u16(value16) && value16 == 0x3456, "byte_reader u16 mismatch");
    expect(reader.read_u24(value24) && value24 == 0x789abc, "byte_reader u24 mismatch");

    const auto bytes = reader.read_bytes(2);
    expect(bytes && (*bytes)[0] == 0xde && (*bytes)[1] == 1, "byte_reader bytes mismatch");
    expect(reader.skip(2), "byte_reader skip failed");
    expect(reader.remaining() == 1, "byte_reader remaining mismatch");
    expect(!reader.read_bytes(2), "byte_reader accepted truncated bytes");
    expect(reader.read_u8(value8) && value8 == 4 && reader.empty(), "byte_reader final byte mismatch");
    expect(!reader.read_u8(value8), "byte_reader accepted read past end");

    expect(rv::core::read_be32(kInput.data()) == 0x12345678U, "byte_order u32 mismatch");
}

void test_hkdf_rfc5869()
{
    boost::system::error_code ec;
    std::vector<std::uint8_t> ikm(22, 0x0b);
    constexpr std::array<std::uint8_t, 13> kSalt{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    constexpr std::array<std::uint8_t, 10> kInfo{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    constexpr std::array<std::uint8_t, 32> kExpectedPrk{0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f,
                                                        0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f,
                                                        0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    constexpr std::array<std::uint8_t, 42> kExpectedOkm{0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                                                        0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                                                        0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    const auto prk = rv::crypto::hkdf_extract(rv::crypto::hash_algorithm::kSha256, kSalt, ikm, ec);
    expect(!ec && std::equal(prk.begin(), prk.end(), kExpectedPrk.begin()), "HKDF-Extract vector mismatch");
    const auto okm = rv::crypto::hkdf_expand(rv::crypto::hash_algorithm::kSha256, prk, kInfo, kExpectedOkm.size(), ec);
    expect(!ec && std::equal(okm.begin(), okm.end(), kExpectedOkm.begin()), "HKDF-Expand vector mismatch");
}

void test_record_roundtrip()
{
    boost::system::error_code ec;
    constexpr std::array kSuites{rv::reality::cipher_suite::kTlsAes128GcmSha256,
                                 rv::reality::cipher_suite::kTlsAes256GcmSha384,
                                 rv::reality::cipher_suite::kTlsChacha20Poly1305Sha256};
    constexpr std::array<std::uint8_t, 7> kMessage{'p', 'a', 'y', 'l', 'o', 'a', 'd'};

    for (const auto suite : kSuites)
    {
        std::vector<std::uint8_t> secret(rv::crypto::hash_size(rv::reality::cipher_properties(suite).hash), 1);
        rv::reality::record_key writer(suite, secret, ec);
        expect(!ec, "record writer construction failed");
        rv::reality::record_key reader(suite, secret, ec);
        expect(!ec, "record reader construction failed");
        const auto wire = writer.seal(rv::tls::kRecordApplicationData, kMessage, ec);
        expect(!ec && wire.size() > 5, "TLS record seal failed");
        const auto header = std::span<const std::uint8_t, 5>(wire.data(), 5);
        const auto opened = reader.open(header, std::span(wire).subspan(5), ec);
        expect(!ec, "TLS record open failed");
        expect(opened.inner_type == rv::tls::kRecordApplicationData, "TLS inner type mismatch");
        expect(opened.content == std::vector<std::uint8_t>(kMessage.begin(), kMessage.end()), "TLS plaintext mismatch");

        std::vector<std::uint8_t> maximum_plaintext(16384, 0x5a);
        const auto maximum_wire = writer.seal(rv::tls::kRecordApplicationData, maximum_plaintext, ec);
        expect(!ec && maximum_wire.size() == 16406, "maximum TLS record seal failed");
        const auto maximum_header = std::span<const std::uint8_t, 5>(maximum_wire.data(), 5);
        const auto maximum_opened = reader.open(maximum_header, std::span(maximum_wire).subspan(5), ec);
        expect(!ec && maximum_opened.content == maximum_plaintext, "maximum TLS record roundtrip failed");

        rv::reality::record_key tamper_writer(suite, secret, ec);
        rv::reality::record_key tamper_reader(suite, secret, ec);
        auto tampered = tamper_writer.seal(rv::tls::kRecordApplicationData, kMessage, ec);
        tampered.back() ^= 0x80;
        const auto tamper_header = std::span<const std::uint8_t, 5>(tampered.data(), 5);
        static_cast<void>(tamper_reader.open(tamper_header, std::span(tampered).subspan(5), ec));
        expect_error(ec, boost::system::errc::bad_message, "TLS tamper returned wrong error");
    }

    constexpr std::array<std::uint8_t, 3> kKeyLabel{'k', 'e', 'y'};
    constexpr std::array<std::uint8_t, 2> kIvLabel{'i', 'v'};
    constexpr std::array<std::uint8_t, 5> kOversizedRecordHeader{0x17, 0x03, 0x03, 0x40, 0x12};
    std::vector<std::uint8_t> oversized_secret(32, 1);
    const auto oversized_key = rv::reality::hkdf_expand_label(rv::crypto::hash_algorithm::kSha256, oversized_secret, kKeyLabel, {}, 16, ec);
    expect(!ec, "oversized TLS record key derivation failed");
    const auto initial_nonce = rv::reality::hkdf_expand_label(rv::crypto::hash_algorithm::kSha256, oversized_secret, kIvLabel, {}, 12, ec);
    expect(!ec, "oversized TLS record nonce derivation failed");
    std::vector<std::uint8_t> oversized_inner(16385, 0x5a);
    oversized_inner.push_back(0x17);
    rv::crypto::aead oversized_cipher(rv::crypto::aead_algorithm::kAes128Gcm, oversized_key, ec);
    expect(!ec, "oversized TLS record cipher construction failed");
    const auto oversized_ciphertext = oversized_cipher.seal(initial_nonce, oversized_inner, kOversizedRecordHeader, ec);
    expect(!ec && oversized_ciphertext.size() == 16402, "oversized TLS record construction failed");

    rv::reality::record_key oversized_reader(rv::reality::cipher_suite::kTlsAes128GcmSha256, oversized_secret, ec);
    expect(!ec, "oversized TLS record reader construction failed");
    static_cast<void>(oversized_reader.open(kOversizedRecordHeader, oversized_ciphertext, ec));
    expect_error(ec, boost::system::errc::message_size, "TLS record accepted oversized inner plaintext");
}

void test_finished_verification()
{
    boost::system::error_code ec;
    constexpr std::array<std::uint8_t, 5> kTranscript{1, 2, 3, 4, 5};
    std::vector<std::uint8_t> secret(rv::crypto::kSha256DigestSize, 7);
    const auto verify_data = rv::reality::finished_verify_data(rv::reality::cipher_suite::kTlsAes128GcmSha256, secret, kTranscript, ec);
    expect(!ec && verify_data.size() == 32, "Finished verify data construction failed");

    rv::reality::verify_finished_data(rv::reality::cipher_suite::kTlsAes128GcmSha256, secret, kTranscript, verify_data, ec);
    expect(!ec, "Finished verification rejected valid data");

    rv::reality::verify_finished_data(
        rv::reality::cipher_suite::kTlsAes128GcmSha256, secret, kTranscript, std::span(verify_data).first(verify_data.size() - 1), ec);
    expect_error(ec, boost::system::errc::bad_message, "Finished length returned wrong error");

    auto invalid_verify_data = verify_data;
    invalid_verify_data[0] ^= 0x80;
    rv::reality::verify_finished_data(rv::reality::cipher_suite::kTlsAes128GcmSha256, secret, kTranscript, invalid_verify_data, ec);
    expect_error(ec, boost::system::errc::permission_denied, "Finished authentication returned wrong error");
}

void test_client_hello()
{
    boost::system::error_code ec;
    rv::reality::client_config config;
    config.server_name = "www.example.com";
    const auto server_key = rv::crypto::make_x25519_key_pair();
    config.server_public_key = server_key.public_key;
    config.short_id = {0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    const auto hello = rv::reality::build_client_hello(config, ec, std::chrono::system_clock::time_point(std::chrono::seconds(1'700'000'000)));
    expect(!ec && hello.has_value(), "ClientHello construction failed");

    const auto wire = std::span<const std::uint8_t>(hello->handshake_bytes);
    expect(wire.size() > 111 && wire[0] == 0x01, "ClientHello wire mismatch");
    expect(read_test_u24(wire, 1, "ClientHello length missing") == wire.size() - 4, "ClientHello handshake length mismatch");
    expect(wire[4] == 0x03 && wire[5] == 0x03, "ClientHello legacy version mismatch");
    expect(wire[38] == hello->session_id.size(), "ClientHello session ID length mismatch");
    expect(std::equal(hello->session_id.begin(), hello->session_id.end(), wire.begin() + 39), "ClientHello session ID mismatch");

    constexpr std::array<std::uint16_t, 17> kExpectedCiphers{
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035};
    std::size_t position = 71;
    expect(read_test_u16(wire, position, "ClientHello cipher length missing") == kExpectedCiphers.size() * 2, "ClientHello cipher length mismatch");
    position += 2;
    for (const auto expected : kExpectedCiphers)
    {
        expect(read_test_u16(wire, position, "ClientHello cipher missing") == expected, "ClientHello cipher order mismatch");
        position += 2;
    }

    constexpr std::array<std::uint8_t, 2> kExpectedCompression{1, 0};
    expect_bytes(test_subspan(wire, position, kExpectedCompression.size(), "ClientHello compression missing"),
                 kExpectedCompression,
                 "ClientHello compression mismatch");
    position += 2;

    const auto extensions_length = read_test_u16(wire, position, "ClientHello extensions length missing");
    position += 2;
    expect(extensions_length == wire.size() - position, "ClientHello extensions length mismatch");

    constexpr std::array<std::uint16_t, 15> kExpectedExtensionTypes{
        0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0xfe0d};
    std::array<std::span<const std::uint8_t>, kExpectedExtensionTypes.size()> extension_data{};
    for (std::size_t index = 0; index != kExpectedExtensionTypes.size(); ++index)
    {
        expect(read_test_u16(wire, position, "ClientHello extension type missing") == kExpectedExtensionTypes[index],
               "ClientHello extension order mismatch");
        position += 2;
        const auto extension_length = read_test_u16(wire, position, "ClientHello extension length missing");
        position += 2;
        extension_data[index] = test_subspan(wire, position, extension_length, "ClientHello extension truncated");
        position += extension_length;
    }
    expect(position == wire.size(), "ClientHello contains unexpected extensions");

    const auto sni = extension_data[0];
    expect(sni.size() == 20, "ClientHello SNI size mismatch");
    expect(read_test_u16(sni, 0, "ClientHello SNI list missing") == 18 && sni[2] == 0x00 &&
               read_test_u16(sni, 3, "ClientHello SNI name length missing") == config.server_name.size() &&
               std::equal(config.server_name.begin(), config.server_name.end(), sni.begin() + 5),
           "ClientHello SNI mismatch");

    constexpr std::array<std::uint8_t, 14> kExpectedGroups{0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01};
    expect_bytes(extension_data[3], kExpectedGroups, "ClientHello supported groups mismatch");

    constexpr std::array<std::uint8_t, 14> kExpectedAlpn{0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    expect_bytes(extension_data[6], kExpectedAlpn, "ClientHello ALPN mismatch");

    expect(extension_data[1].empty() && extension_data[5].empty(), "ClientHello empty extension mismatch");
    constexpr std::array<std::uint8_t, 1> kExpectedRenegotiation{0x00};
    expect_bytes(extension_data[2], kExpectedRenegotiation, "ClientHello renegotiation extension mismatch");
    constexpr std::array<std::uint8_t, 2> kExpectedPointFormats{0x01, 0x00};
    expect_bytes(extension_data[4], kExpectedPointFormats, "ClientHello point formats mismatch");
    constexpr std::array<std::uint8_t, 5> kExpectedStatusRequest{0x01, 0x00, 0x00, 0x00, 0x00};
    expect_bytes(extension_data[7], kExpectedStatusRequest, "ClientHello status request mismatch");
    constexpr std::array<std::uint8_t, 10> kExpectedDelegatedCredentials{0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03};
    expect_bytes(extension_data[8], kExpectedDelegatedCredentials, "ClientHello delegated credentials mismatch");

    const auto key_share = extension_data[9];
    expect(key_share.size() == 107 && read_test_u16(key_share, 0, "ClientHello key share list missing") == 105,
           "ClientHello key share length mismatch");
    expect(read_test_u16(key_share, 2, "ClientHello X25519 group missing") == 0x001d &&
               read_test_u16(key_share, 4, "ClientHello X25519 length missing") == 32,
           "ClientHello X25519 key share mismatch");
    expect(read_test_u16(key_share, 38, "ClientHello P-256 group missing") == 0x0017 &&
               read_test_u16(key_share, 40, "ClientHello P-256 length missing") == 65 && key_share[42] == 0x04,
           "ClientHello P-256 key share mismatch");

    constexpr std::array<std::uint8_t, 5> kExpectedVersions{0x04, 0x03, 0x04, 0x03, 0x03};
    expect_bytes(extension_data[10], kExpectedVersions, "ClientHello supported versions mismatch");

    constexpr std::array<std::uint8_t, 24> kExpectedSignatures{0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05,
                                                               0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01};
    expect_bytes(extension_data[11], kExpectedSignatures, "ClientHello signature algorithms mismatch");

    constexpr std::array<std::uint8_t, 2> kExpectedPskModes{0x01, 0x01};
    expect_bytes(extension_data[12], kExpectedPskModes, "ClientHello PSK mode mismatch");

    constexpr std::array<std::uint8_t, 2> kExpectedRecordSizeLimit{0x40, 0x01};
    expect_bytes(extension_data[13], kExpectedRecordSizeLimit, "ClientHello record size limit mismatch");

    const auto ech = extension_data[14];
    expect(ech.size() == 281 && ech[0] == 0x00, "ClientHello ECH size mismatch");
    expect(read_test_u16(ech, 1, "ClientHello ECH KDF missing") == 0x0001, "ClientHello ECH KDF mismatch");
    const auto aead_id = read_test_u16(ech, 3, "ClientHello ECH AEAD missing");
    expect(aead_id == 0x0001 || aead_id == 0x0003, "ClientHello ECH AEAD mismatch");
    expect(read_test_u16(ech, 6, "ClientHello ECH encapsulated length missing") == 32 &&
               read_test_u16(ech, 40, "ClientHello ECH payload length missing") == 239,
           "ClientHello ECH payload shape mismatch");
}

void test_vless_header()
{
    boost::system::error_code ec;
    rv::vless::client_config config;
    config.user_id.fill(0x11);
    config.destination = rv::net::domain_address{"example.com"};
    config.destination_port = 443;

    const auto request = rv::vless::encode_tcp_request(config, ec);
    std::vector<std::uint8_t> expected_tcp{0x00};
    expected_tcp.insert(expected_tcp.end(), config.user_id.begin(), config.user_id.end());
    constexpr std::array<std::uint8_t, 3> kVisionPrefix{0x12, 0x0a, 0x10};
    expected_tcp.insert(expected_tcp.end(), kVisionPrefix.begin(), kVisionPrefix.end());
    constexpr std::string_view kVisionFlow = "xtls-rprx-vision";
    expected_tcp.insert(expected_tcp.end(), kVisionFlow.begin(), kVisionFlow.end());
    constexpr std::array<std::uint8_t, 5> kTcpDestinationPrefix{0x01, 0x01, 0xbb, 0x02, 0x0b};
    expected_tcp.insert(expected_tcp.end(), kTcpDestinationPrefix.begin(), kTcpDestinationPrefix.end());
    constexpr std::string_view kDomain = "example.com";
    expected_tcp.insert(expected_tcp.end(), kDomain.begin(), kDomain.end());
    expect(!ec && request == expected_tcp, "VLESS TCP Vision header mismatch");

    config.destination_port = 53;
    const auto udp_request = rv::vless::encode_udp_request(config, ec);
    std::vector<std::uint8_t> expected_udp{0x00};
    expected_udp.insert(expected_udp.end(), config.user_id.begin(), config.user_id.end());
    constexpr std::array<std::uint8_t, 6> kUdpDestinationPrefix{0x00, 0x02, 0x00, 0x35, 0x02, 0x0b};
    expected_udp.insert(expected_udp.end(), kUdpDestinationPrefix.begin(), kUdpDestinationPrefix.end());
    expected_udp.insert(expected_udp.end(), kDomain.begin(), kDomain.end());
    expect(!ec && udp_request == expected_udp, "VLESS UDP header mismatch");

    config.destination = rv::net::ipv4_address{{192, 0, 2, 1}};
    const auto ipv4_request = rv::vless::encode_udp_request(config, ec);
    expect(!ec, "VLESS IPv4 encoding failed");
    constexpr std::array<std::uint8_t, 7> kExpectedIpv4Suffix{0x00, 0x35, 0x01, 192, 0, 2, 1};
    expect(ipv4_request.size() >= kExpectedIpv4Suffix.size() &&
               std::equal(kExpectedIpv4Suffix.begin(), kExpectedIpv4Suffix.end(), ipv4_request.end() - kExpectedIpv4Suffix.size()),
           "VLESS IPv4 address mismatch");

    config.destination = rv::net::ipv6_address{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
    config.destination_port = 443;
    const auto ipv6_request = rv::vless::encode_udp_request(config, ec);
    expect(!ec, "VLESS IPv6 encoding failed");
    constexpr std::array<std::uint8_t, 19> kExpectedIpv6Suffix{0x01, 0xbb, 0x03, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    expect(ipv6_request.size() >= kExpectedIpv6Suffix.size() &&
               std::equal(kExpectedIpv6Suffix.begin(), kExpectedIpv6Suffix.end(), ipv6_request.end() - kExpectedIpv6Suffix.size()),
           "VLESS IPv6 address mismatch");

    config.destination = rv::net::domain_address{};
    static_cast<void>(rv::vless::encode_tcp_request(config, ec));
    expect_error(ec, boost::system::errc::invalid_argument, "VLESS empty domain returned wrong error");

    config.destination = rv::net::domain_address{std::string("bad\0domain", 10)};
    static_cast<void>(rv::vless::encode_tcp_request(config, ec));
    expect_error(ec, boost::system::errc::invalid_argument, "VLESS embedded NUL domain returned wrong error");

    config.destination = rv::net::domain_address{std::string(255, 'a')};
    const auto maximum_domain_request = rv::vless::encode_tcp_request(config, ec);
    expect(!ec && !maximum_domain_request.empty(), "VLESS maximum domain length rejected");

    config.destination = rv::net::domain_address{std::string(256, 'a')};
    static_cast<void>(rv::vless::encode_tcp_request(config, ec));
    expect_error(ec, boost::system::errc::invalid_argument, "VLESS oversized domain returned wrong error");

    config.destination = rv::net::domain_address{"example.com"};
    config.destination_port = 0;
    static_cast<void>(rv::vless::encode_tcp_request(config, ec));
    expect_error(ec, boost::system::errc::invalid_argument, "VLESS zero port returned wrong error");
}

void put_test_u16(const std::size_t value, std::vector<std::uint8_t>& output)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void put_test_u24(const std::size_t value, std::vector<std::uint8_t>& output)
{
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

void append_test_tls_record(const std::span<const std::uint8_t> payload, std::vector<std::uint8_t>& output)
{
    output.push_back(0x16);
    output.push_back(0x03);
    output.push_back(0x01);
    put_test_u16(payload.size(), output);
    output.insert(output.end(), payload.begin(), payload.end());
}

std::vector<std::uint8_t> make_test_tls_client_hello(const std::string_view domain)
{
    std::vector<std::uint8_t> server_name;
    put_test_u16(1 + 2 + domain.size(), server_name);
    server_name.push_back(0x00);
    put_test_u16(domain.size(), server_name);
    server_name.insert(server_name.end(), domain.begin(), domain.end());

    std::vector<std::uint8_t> extensions;
    put_test_u16(0x0000, extensions);
    put_test_u16(server_name.size(), extensions);
    extensions.insert(extensions.end(), server_name.begin(), server_name.end());

    std::vector<std::uint8_t> body;
    body.push_back(0x03);
    body.push_back(0x03);
    body.insert(body.end(), 32, 0x11);
    body.push_back(0x00);
    put_test_u16(2, body);
    body.push_back(0x13);
    body.push_back(0x01);
    body.push_back(1);
    body.push_back(0x00);
    put_test_u16(extensions.size(), body);
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake;
    handshake.push_back(0x01);
    put_test_u24(body.size(), handshake);
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<std::uint8_t> wire;
    append_test_tls_record(handshake, wire);
    return wire;
}

std::vector<std::uint8_t> make_test_tls_server_hello(const std::uint16_t cipher, const bool tls13)
{
    std::vector<std::uint8_t> extensions;
    put_test_u16(0x002b, extensions);
    put_test_u16(2, extensions);
    extensions.push_back(0x03);
    extensions.push_back(tls13 ? 0x04 : 0x03);

    std::vector<std::uint8_t> body;
    body.push_back(0x03);
    body.push_back(0x03);
    body.insert(body.end(), 32, 0x22);
    body.push_back(32);
    body.insert(body.end(), 32, 0x33);
    put_test_u16(cipher, body);
    body.push_back(0x00);
    put_test_u16(extensions.size(), body);
    body.insert(body.end(), extensions.begin(), extensions.end());

    std::vector<std::uint8_t> handshake;
    handshake.push_back(0x02);
    put_test_u24(body.size(), handshake);
    handshake.insert(handshake.end(), body.begin(), body.end());

    std::vector<std::uint8_t> wire{0x16, 0x03, 0x03};
    put_test_u16(handshake.size(), wire);
    wire.insert(wire.end(), handshake.begin(), handshake.end());
    return wire;
}

void test_destination_sniffer()
{
    constexpr std::string_view kHttpRequest = "GET / HTTP/1.1\r\nHoSt: example.com:443\r\nUser-Agent: test\r\n\r\n";
    auto result = rv::sniff::inspect_destination(std::span(reinterpret_cast<const std::uint8_t*>(kHttpRequest.data()), 2));
    expect(result.state == rv::sniff::status::kNeedMore, "destination sniffer rejected a fragmented HTTP method");

    result = rv::sniff::inspect_destination(std::span(reinterpret_cast<const std::uint8_t*>(kHttpRequest.data()), kHttpRequest.size()));
    expect(result.state == rv::sniff::status::kFound && result.domain == "example.com", "destination sniffer missed HTTP Host");

    const auto tls_client_hello = make_test_tls_client_hello("example.com");
    for (std::size_t size = 1; size != tls_client_hello.size(); ++size)
    {
        result = rv::sniff::inspect_destination(std::span(tls_client_hello).first(size));
        expect(result.state == rv::sniff::status::kNeedMore, "destination sniffer rejected fragmented TLS ClientHello");
    }
    result = rv::sniff::inspect_destination(tls_client_hello);
    expect(result.state == rv::sniff::status::kFound && result.domain == "example.com", "destination sniffer missed TLS SNI");

    constexpr std::string_view kSshBanner = "SSH-2.0-test\r\n";
    result = rv::sniff::inspect_destination(std::span(reinterpret_cast<const std::uint8_t*>(kSshBanner.data()), kSshBanner.size()));
    expect(result.state == rv::sniff::status::kNoMatch, "destination sniffer accepted an unrelated protocol");
}

void test_vision_frame_codec()
{
    boost::system::error_code ec;
    std::array<std::uint8_t, rv::vision::kUserIdSize> user_id{};
    user_id.fill(0x42);
    constexpr std::array<std::uint8_t, 4> kContent{1, 2, 3, 4};

    const auto frame = rv::vision::encode_frame(
        rv::vision::command::kEndPadding, std::span<const std::uint8_t, rv::vision::kUserIdSize>(user_id), kContent, false, ec);
    expect(!ec && frame.size() >= rv::vision::kFullHeaderSize + kContent.size() && frame.size() <= rv::vision::kXrayBufferSize,
           "Vision full frame encode failed");

    rv::vision::frame_header header;
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(frame.data(), rv::vision::kFullHeaderSize), true, user_id, header);
    expect(!ec, "Vision full header decode failed");
    expect(header.frame_command == rv::vision::command::kEndPadding, "Vision full header command mismatch");
    expect(header.content_length == kContent.size(), "Vision full header content length mismatch");
    expect(frame.size() == rv::vision::kFullHeaderSize + header.content_length + header.padding_length, "Vision full frame length mismatch");
    expect(header.padding_length <= 255, "Vision short padding length mismatch");
    const auto padding = std::span(frame).subspan(rv::vision::kFullHeaderSize + header.content_length);
    expect(std::all_of(padding.begin(), padding.end(), [](const std::uint8_t byte) { return byte == 0; }), "Vision padding contains non-zero data");

    auto wrong_user = user_id;
    wrong_user[0] ^= 1;
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(frame.data(), rv::vision::kFullHeaderSize), true, wrong_user, header);
    expect_error(ec, boost::system::errc::permission_denied, "Vision wrong user returned wrong error");

    for (const auto frame_command : std::array{rv::vision::command::kContinuePadding, rv::vision::command::kEndPadding, rv::vision::command::kDirect})
    {
        auto header_bytes = std::array<std::uint8_t, rv::vision::kShortHeaderSize>{};
        header_bytes[0] = static_cast<std::uint8_t>(frame_command);
        ec = rv::vision::decode_header(header_bytes, false, user_id, header);
        expect(!ec && header.frame_command == frame_command, "Vision command decode mismatch");
    }

    ec.clear();
    const auto short_frame = rv::vision::encode_frame(rv::vision::command::kDirect, std::nullopt, kContent, false, ec);
    expect(!ec && short_frame.size() >= rv::vision::kShortHeaderSize + kContent.size(), "Vision short frame encode failed");
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(short_frame.data(), rv::vision::kShortHeaderSize), false, user_id, header);
    expect(!ec && header.frame_command == rv::vision::command::kDirect && header.content_length == kContent.size(),
           "Vision short header decode mismatch");

    constexpr std::array<std::uint8_t, rv::vision::kShortHeaderSize> kInvalidCommand{0x03, 0x00, 0x00, 0x00, 0x00};
    ec = rv::vision::decode_header(kInvalidCommand, false, user_id, header);
    expect_error(ec, boost::system::errc::bad_message, "Vision invalid command returned wrong error");

    constexpr std::array<std::uint8_t, rv::vision::kShortHeaderSize> kOversizedHeader{0x00, 0x1f, 0xfe, 0x00, 0x00};
    ec = rv::vision::decode_header(kOversizedHeader, false, user_id, header);
    expect_error(ec, boost::system::errc::message_size, "Vision oversized frame header returned wrong error");

    const std::vector<std::uint8_t> oversized_content(rv::vision::kXrayBufferSize - rv::vision::kShortHeaderSize + 1, 0x55);
    ec.clear();
    static_cast<void>(rv::vision::encode_frame(rv::vision::command::kContinuePadding, std::nullopt, oversized_content, false, ec));
    expect_error(ec, boost::system::errc::message_size, "Vision encoder accepted oversized content");

    ec.clear();
    const auto long_padding_frame = rv::vision::encode_frame(
        rv::vision::command::kContinuePadding, std::span<const std::uint8_t, rv::vision::kUserIdSize>(user_id), kContent, true, ec);
    expect(!ec, "Vision long padding encode failed");
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(long_padding_frame.data(), rv::vision::kFullHeaderSize), true, user_id, header);
    expect(!ec && header.padding_length >= 900 - kContent.size() && header.padding_length < 1400 - kContent.size(),
           "Vision long padding length mismatch");
}

void test_vision_tls_trackers()
{
    rv::vision::client_tls_record_tracker tracker;
    constexpr std::array<std::uint8_t, 9> kClientHello{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};

    auto observation = tracker.observe(std::span(kClientHello).first(2));
    expect(observation.kind == rv::vision::client_stream_kind::kUndecided, "TLS tracker decided too early");

    observation = tracker.observe(std::span(kClientHello).subspan(2, 3));
    expect(observation.kind == rv::vision::client_stream_kind::kUndecided, "TLS tracker decided without payload");

    observation = tracker.observe(std::span(kClientHello).subspan(5, 1));
    expect(observation.kind == rv::vision::client_stream_kind::kTls, "TLS tracker missed fragmented ClientHello");

    observation = tracker.observe(std::span(kClientHello).subspan(6));
    expect(!observation.encrypted_record_end_offset, "TLS tracker reported a handshake record as encrypted");

    constexpr std::array<std::uint8_t, 13> kCcsAndPartialEncrypted{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb};
    observation = tracker.observe(kCcsAndPartialEncrypted);
    expect(!observation.encrypted_record_end_offset, "TLS tracker accepted a partial encrypted record");

    constexpr std::array<std::uint8_t, 6> kEncryptedTailAndNextHeader{0xcc, 0xdd, 0x17, 0x03, 0x03, 0x00};
    observation = tracker.observe(kEncryptedTailAndNextHeader);
    expect(observation.encrypted_record_end_offset && *observation.encrypted_record_end_offset == 2,
           "TLS tracker returned the wrong cross-call record boundary");

    rv::vision::client_tls_record_tracker non_tls_tracker;
    constexpr std::array<std::uint8_t, 2> kHttpPrefix{'G', 'E'};
    observation = non_tls_tracker.observe(kHttpPrefix);
    expect(observation.kind == rv::vision::client_stream_kind::kUndecided, "TLS tracker rejected a short prefix too early");

    constexpr std::array<std::uint8_t, 3> kHttpSuffix{'T', ' ', '/'};
    observation = non_tls_tracker.observe(kHttpSuffix);
    expect(observation.kind == rv::vision::client_stream_kind::kNonTls, "TLS tracker failed to classify HTTP");

    rv::vision::client_tls_record_tracker malformed_tracker;
    observation = malformed_tracker.observe(kClientHello);
    expect(observation.kind == rv::vision::client_stream_kind::kTls, "TLS tracker failed a complete ClientHello");

    constexpr std::array<std::uint8_t, 5> kInvalidRecordHeader{0x99, 0x03, 0x03, 0x00, 0x01};
    observation = malformed_tracker.observe(kInvalidRecordHeader);
    expect(observation.tracking_failed, "TLS tracker did not report loss of record framing");

    for (const auto cipher : std::array<std::uint16_t, 4>{0x1301, 0x1302, 0x1303, 0x1304})
    {
        rv::vision::server_hello_tracker server_tracker;
        const auto server_hello = make_test_tls_server_hello(cipher, true);
        server_tracker.observe(server_hello);
        expect(server_tracker.direct_supported(), "Vision server tracker rejected a Direct TLS 1.3 cipher");
    }

    rv::vision::server_hello_tracker ccm8_tracker;
    ccm8_tracker.observe(make_test_tls_server_hello(0x1305, true));
    expect(!ccm8_tracker.direct_supported(), "Vision server tracker accepted TLS_AES_128_CCM_8_SHA256");

    rv::vision::server_hello_tracker tls12_tracker;
    tls12_tracker.observe(make_test_tls_server_hello(0x1301, false));
    expect(!tls12_tracker.direct_supported(), "Vision server tracker accepted TLS 1.2");

    auto false_positive_server_hello = make_test_tls_server_hello(0x1301, false);
    constexpr std::array<std::uint8_t, 6> kTls13ExtensionBytes{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    std::copy(kTls13ExtensionBytes.begin(), kTls13ExtensionBytes.end(), false_positive_server_hello.begin() + 11);
    rv::vision::server_hello_tracker false_positive_tracker;
    false_positive_tracker.observe(false_positive_server_hello);
    expect(!false_positive_tracker.direct_supported(), "Vision server tracker matched TLS 1.3 bytes outside the extension list");

    const auto fragmented_server_hello = make_test_tls_server_hello(0x1303, true);
    rv::vision::server_hello_tracker fragmented_tracker;
    constexpr std::array<std::uint8_t, 3> kPrefix{0xaa, 0xbb, 0xcc};
    fragmented_tracker.observe(kPrefix);
    fragmented_tracker.observe(std::span(fragmented_server_hello).first(2));
    expect(!fragmented_tracker.direct_supported(), "Vision server tracker decided before a complete record header");
    fragmented_tracker.observe(std::span(fragmented_server_hello).subspan(2, 3));
    expect(!fragmented_tracker.direct_supported(), "Vision server tracker decided without a handshake type");
    fragmented_tracker.observe(std::span(fragmented_server_hello).subspan(5, 7));
    expect(!fragmented_tracker.direct_supported(), "Vision server tracker decided on a partial ServerHello");
    fragmented_tracker.observe(std::span(fragmented_server_hello).subspan(12));
    expect(fragmented_tracker.direct_supported(), "Vision server tracker missed a fragmented ServerHello");
}

void test_socks5_request_decode()
{
    boost::system::error_code ec;
    rv::socks5::request request;

    constexpr std::array<std::uint8_t, 10> kIpv4Request{5, 1, 0, 1, 127, 0, 0, 1, 0x01, 0xbb};
    ec = rv::socks5::decode_request(kIpv4Request, request);
    expect(!ec, "SOCKS5 IPv4 CONNECT decode failed");
    expect(request.requested_command == rv::socks5::command::kConnect, "SOCKS5 CONNECT command mismatch");
    expect(request.port == 443, "SOCKS5 IPv4 CONNECT port mismatch");
    const auto* ipv4 = std::get_if<rv::net::ipv4_address>(&request.destination);
    expect(ipv4 != nullptr && ipv4->bytes == std::array<std::uint8_t, 4>{127, 0, 0, 1}, "SOCKS5 IPv4 CONNECT address mismatch");

    constexpr std::array<std::uint8_t, 18> kDomainRequest{
        5,
        1,
        0,
        3,
        11,
        'e',
        'x',
        'a',
        'm',
        'p',
        'l',
        'e',
        '.',
        'c',
        'o',
        'm',
        0x01,
        0xbb,
    };
    ec = rv::socks5::decode_request(kDomainRequest, request);
    expect(!ec, "SOCKS5 domain CONNECT decode failed");
    const auto* domain = std::get_if<rv::net::domain_address>(&request.destination);
    expect(domain != nullptr && domain->name == "example.com" && request.port == 443, "SOCKS5 domain CONNECT mismatch");

    constexpr std::array<std::uint8_t, 22> kIpv6Request{
        5, 1, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x01, 0xbb,
    };
    ec = rv::socks5::decode_request(kIpv6Request, request);
    expect(!ec, "SOCKS5 IPv6 CONNECT decode failed");
    const auto* ipv6 = std::get_if<rv::net::ipv6_address>(&request.destination);
    constexpr std::array<std::uint8_t, 16> kExpectedIpv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    expect(ipv6 != nullptr && ipv6->bytes == kExpectedIpv6 && request.port == 443, "SOCKS5 IPv6 CONNECT mismatch");

    constexpr std::array<std::uint8_t, 10> kAssociate{5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
    ec = rv::socks5::decode_request(kAssociate, request);
    expect(!ec, "SOCKS5 UDP ASSOCIATE decode failed");
    expect(request.requested_command == rv::socks5::command::kUdpAssociate && request.port == 0, "SOCKS5 UDP ASSOCIATE command mismatch");

    auto malformed = kIpv4Request;
    malformed[0] = 4;
    ec = rv::socks5::decode_request(malformed, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted wrong version");

    malformed = kIpv4Request;
    malformed[2] = 1;
    ec = rv::socks5::decode_request(malformed, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted nonzero reserved byte");

    malformed = kIpv4Request;
    malformed[1] = 2;
    ec = rv::socks5::decode_request(malformed, request);
    expect_error(ec, boost::system::errc::operation_not_supported, "SOCKS5 unsupported command returned wrong error");

    malformed = kIpv4Request;
    malformed[3] = 2;
    ec = rv::socks5::decode_request(malformed, request);
    expect_error(ec, boost::system::errc::address_family_not_supported, "SOCKS5 unsupported address type returned wrong error");

    constexpr std::array<std::uint8_t, 9> kTruncatedIpv4{5, 1, 0, 1, 127, 0, 0, 1, 0x01};
    ec = rv::socks5::decode_request(kTruncatedIpv4, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted truncated IPv4 request");

    constexpr std::array<std::uint8_t, 7> kEmptyDomain{5, 1, 0, 3, 0, 0, 80};
    ec = rv::socks5::decode_request(kEmptyDomain, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted empty domain");

    constexpr std::array<std::uint8_t, 10> kNulDomain{5, 1, 0, 3, 3, 'a', 0, 'b', 0, 80};
    ec = rv::socks5::decode_request(kNulDomain, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted domain containing NUL");

    constexpr std::array<std::uint8_t, 11> kTrailingBytes{5, 1, 0, 1, 127, 0, 0, 1, 0, 80, 0};
    ec = rv::socks5::decode_request(kTrailingBytes, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted trailing request bytes");

    constexpr std::array<std::uint8_t, 10> kZeroConnectPort{5, 1, 0, 1, 127, 0, 0, 1, 0, 0};
    ec = rv::socks5::decode_request(kZeroConnectPort, request);
    expect_error(ec, boost::system::errc::invalid_argument, "SOCKS5 CONNECT accepted port zero");
}

void test_socks5_udp_codec()
{
    boost::system::error_code ec;
    rv::socks5::udp_datagram datagram;

    constexpr std::array<std::uint8_t, 13> kIpv4Packet{0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 'd', 'n', 's'};
    ec = rv::socks5::decode_udp_datagram(kIpv4Packet, datagram);
    expect(!ec && datagram.port == 53 && datagram.payload.size() == 3, "SOCKS5 IPv4 UDP datagram decode failed");
    const auto encoded_ipv4 = rv::socks5::encode_udp_datagram(datagram.destination, datagram.port, datagram.payload, ec);
    expect(!ec && encoded_ipv4 == std::vector<std::uint8_t>(kIpv4Packet.begin(), kIpv4Packet.end()), "SOCKS5 IPv4 UDP roundtrip mismatch");

    constexpr std::array<std::uint8_t, 12> kDomainPacket{0, 0, 0, 3, 3, 'd', 'n', 's', 0, 53, 0xaa, 0xbb};
    ec = rv::socks5::decode_udp_datagram(kDomainPacket, datagram);
    expect(!ec && datagram.port == 53 && datagram.payload.size() == 2, "SOCKS5 domain UDP datagram decode failed");
    const auto* domain = std::get_if<rv::net::domain_address>(&datagram.destination);
    expect(domain != nullptr && domain->name == "dns", "SOCKS5 domain UDP destination mismatch");

    constexpr std::array<std::uint8_t, 25> kIpv6Packet{
        0, 0, 0, 4, 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0, 53, 1, 2, 3,
    };
    ec = rv::socks5::decode_udp_datagram(kIpv6Packet, datagram);
    expect(!ec && datagram.port == 53 && datagram.payload.size() == 3, "SOCKS5 IPv6 UDP datagram decode failed");
    const auto encoded_ipv6 = rv::socks5::encode_udp_datagram(datagram.destination, datagram.port, datagram.payload, ec);
    expect(!ec && encoded_ipv6 == std::vector<std::uint8_t>(kIpv6Packet.begin(), kIpv6Packet.end()), "SOCKS5 IPv6 UDP roundtrip mismatch");

    auto malformed = kIpv4Packet;
    malformed[0] = 1;
    ec = rv::socks5::decode_udp_datagram(malformed, datagram);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 UDP accepted nonzero reserved field");

    malformed = kIpv4Packet;
    malformed[2] = 1;
    ec = rv::socks5::decode_udp_datagram(malformed, datagram);
    expect_error(ec, boost::system::errc::operation_not_supported, "SOCKS5 UDP fragmentation returned wrong error");

    malformed = kIpv4Packet;
    malformed[3] = 2;
    ec = rv::socks5::decode_udp_datagram(malformed, datagram);
    expect_error(ec, boost::system::errc::address_family_not_supported, "SOCKS5 UDP unsupported address type returned wrong error");

    constexpr std::array<std::uint8_t, 9> kTruncatedIpv4{0, 0, 0, 1, 8, 8, 8, 8, 0};
    ec = rv::socks5::decode_udp_datagram(kTruncatedIpv4, datagram);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 UDP accepted truncated datagram");

    constexpr std::array<std::uint8_t, 10> kZeroPort{0, 0, 0, 1, 8, 8, 8, 8, 0, 0};
    ec = rv::socks5::decode_udp_datagram(kZeroPort, datagram);
    expect_error(ec, boost::system::errc::invalid_argument, "SOCKS5 UDP accepted port zero");

    constexpr std::array<std::uint8_t, 10> kNulDomain{0, 0, 0, 3, 3, 'a', 0, 'b', 0, 53};
    ec = rv::socks5::decode_udp_datagram(kNulDomain, datagram);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 UDP accepted domain containing NUL");

    const rv::net::domain_address invalid_domain{std::string("a\0b", 3)};
    const auto invalid_encoded = rv::socks5::encode_udp_datagram(invalid_domain, 53, {}, ec);
    expect(invalid_encoded.empty(), "SOCKS5 UDP encoded domain containing NUL");
    expect_error(ec, boost::system::errc::invalid_argument, "SOCKS5 UDP invalid domain returned wrong encode error");
}

}    // namespace

int run_protocol_tests()
{
    const std::array tests{
        std::pair{"text codecs", &test_text_codecs},
        std::pair{"short id config", &test_short_id_config},
        std::pair{"byte queue", &test_byte_queue},
        std::pair{"byte reader", &test_byte_reader},
        std::pair{"byte writer", &test_byte_writer},
        std::pair{"network address", &test_network_address},
        std::pair{"HKDF", &test_hkdf_rfc5869},
        std::pair{"TLS records", &test_record_roundtrip},
        std::pair{"TLS Finished verification", &test_finished_verification},
        std::pair{"ClientHello", &test_client_hello},
        std::pair{"VLESS header", &test_vless_header},
        std::pair{"destination sniffer", &test_destination_sniffer},
        std::pair{"Vision frame codec", &test_vision_frame_codec},
        std::pair{"Vision TLS trackers", &test_vision_tls_trackers},
        std::pair{"SOCKS5 request decode", &test_socks5_request_decode},
        std::pair{"SOCKS5 UDP codec", &test_socks5_udp_codec},
    };

    try
    {
        for (const auto& [name, test] : tests)
        {
            test();
            spdlog::info("self-test passed: {}", name);
        }
        return 0;
    }
    catch (const std::exception& error)
    {
        spdlog::error("self-test failed: {}", error.what());
        return 1;
    }
}

}    // namespace rv::testing

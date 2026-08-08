#include "protocol_tests.hpp"

#include "base64.hpp"
#include "byte_order.hpp"
#include "byte_queue.hpp"
#include "byte_reader.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "hex.hpp"
#include "reality_client_hello.hpp"
#include "reality_record.hpp"
#include "socks5_protocol.hpp"
#include "sniffer.hpp"
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

std::span<const std::uint8_t> test_subspan(
    const std::span<const std::uint8_t> input,
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

void test_short_id_config()
{
    const auto short_id = parse_short_id_test_config("01234567");
    constexpr std::array<std::uint8_t, 8> expected_short_id{0x01, 0x23, 0x45, 0x67, 0x00, 0x00, 0x00, 0x00};
    expect(short_id.reality_short_id == expected_short_id, "short id zero padding mismatch");

    const auto full_short_id = parse_short_id_test_config("0123456789abcdef");
    constexpr std::array<std::uint8_t, 8> expected_full_short_id{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef};
    expect(full_short_id.reality_short_id == expected_full_short_id, "full short id mismatch");

    const auto empty_short_id = parse_short_id_test_config("");
    expect(empty_short_id.reality_short_id == std::array<std::uint8_t, 8>{}, "empty short id mismatch");
}

void test_text_codecs()
{
    constexpr std::array<std::uint8_t, 3> man{'M', 'a', 'n'};
    expect(rv::core::base64::encode_to_string(man.data(), man.size()) == "TWFu", "Base64 encode mismatch");
    expect(rv::core::base64::encode_url_to_string(man.data(), man.size()) == "TWFu", "Base64URL encode mismatch");

    constexpr std::string_view encoded_binary = "AAEC/w==";
    const auto decoded_binary = rv::core::base64::decode_to_bytes(reinterpret_cast<const std::uint8_t*>(encoded_binary.data()),
                                                                  static_cast<std::uint32_t>(encoded_binary.size()));
    expect(decoded_binary == std::vector<std::uint8_t>({0x00, 0x01, 0x02, 0xff}), "Base64 decode mismatch");

    constexpr std::string_view encoded_url = "AAEC_w";
    const auto decoded_url = rv::core::base64::decode_url_to_bytes(reinterpret_cast<const std::uint8_t*>(encoded_url.data()),
                                                                   static_cast<std::uint32_t>(encoded_url.size()));
    expect(decoded_url == std::vector<std::uint8_t>({0x00, 0x01, 0x02, 0xff}), "Base64URL decode mismatch");

    constexpr std::array<std::uint8_t, 3> raw_hex{0x00, 0xab, 0xff};
    expect(rv::core::hex::encode_to_string(raw_hex.data(), raw_hex.size()) == "00abff", "Hex encode mismatch");
    expect(rv::core::hex::decode_to_bytes("00abff", 6) == std::vector<std::uint8_t>(raw_hex.begin(), raw_hex.end()), "Hex decode mismatch");
    expect(rv::core::hex::decode_to_bytes("abc", 3).empty(), "Hex accepted odd input");
}

void test_byte_queue()
{
    rv::core::byte_queue queue(8);
    boost::system::error_code ec;
    constexpr std::array<std::uint8_t, 5> first{1, 2, 3, 4, 5};
    queue.append(first, ec);
    expect(!ec, "byte_queue append failed");
    std::array<std::uint8_t, 2> prefix{};
    expect(queue.copy_to(prefix) == 2 && prefix == std::array<std::uint8_t, 2>{1, 2}, "byte_queue prefix mismatch");
    constexpr std::array<std::uint8_t, 6> oversized{6, 7, 8, 9, 10, 11};
    queue.append(oversized, ec);
    expect(ec == boost::system::errc::make_error_code(boost::system::errc::message_size), "byte_queue accepted oversized append");
    expect_error(ec, boost::system::errc::message_size, "byte_queue returned wrong error");
}

void test_byte_reader()
{
    constexpr std::array<std::uint8_t, 11> input{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 1, 2, 3, 4};
    rv::core::byte_reader reader(input);

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

    expect(rv::core::read_be32(input.data()) == 0x12345678U, "byte_order u32 mismatch");
}

void test_hkdf_rfc5869()
{
    boost::system::error_code ec;
    std::vector<std::uint8_t> ikm(22, 0x0b);
    constexpr std::array<std::uint8_t, 13> salt{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c};
    constexpr std::array<std::uint8_t, 10> info{0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    constexpr std::array<std::uint8_t, 32> expected_prk{0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f,
                                                        0x0d, 0xc4, 0x7b, 0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f,
                                                        0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5};
    constexpr std::array<std::uint8_t, 42> expected_okm{0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36,
                                                        0x2f, 0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56,
                                                        0xec, 0xc4, 0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65};

    const auto prk = rv::crypto::hkdf_extract(rv::crypto::hash_algorithm::sha256, salt, ikm, ec);
    expect(!ec && std::equal(prk.begin(), prk.end(), expected_prk.begin()), "HKDF-Extract vector mismatch");
    const auto okm = rv::crypto::hkdf_expand(rv::crypto::hash_algorithm::sha256, prk, info, expected_okm.size(), ec);
    expect(!ec && std::equal(okm.begin(), okm.end(), expected_okm.begin()), "HKDF-Expand vector mismatch");
}

void test_record_roundtrip()
{
    boost::system::error_code ec;
    constexpr std::array suites{rv::reality::cipher_suite::tls_aes_128_gcm_sha256,
                                rv::reality::cipher_suite::tls_aes_256_gcm_sha384,
                                rv::reality::cipher_suite::tls_chacha20_poly1305_sha256};
    constexpr std::array<std::uint8_t, 7> message{'p', 'a', 'y', 'l', 'o', 'a', 'd'};

    for (const auto suite : suites)
    {
        std::vector<std::uint8_t> secret(rv::crypto::hash_size(rv::reality::cipher_properties(suite).hash), 1);
        rv::reality::record_key writer(suite, secret, ec);
        expect(!ec, "record writer construction failed");
        rv::reality::record_key reader(suite, secret, ec);
        expect(!ec, "record reader construction failed");
        const auto wire = writer.seal(rv::reality::tls_record_application_data, message, ec);
        expect(!ec && wire.size() > 5, "TLS record seal failed");
        const auto header = std::span<const std::uint8_t, 5>(wire.data(), 5);
        const auto opened = reader.open(header, std::span(wire).subspan(5), ec);
        expect(!ec, "TLS record open failed");
        expect(opened.inner_type == rv::reality::tls_record_application_data, "TLS inner type mismatch");
        expect(opened.content == std::vector<std::uint8_t>(message.begin(), message.end()), "TLS plaintext mismatch");

        rv::reality::record_key tamper_writer(suite, secret, ec);
        rv::reality::record_key tamper_reader(suite, secret, ec);
        auto tampered = tamper_writer.seal(rv::reality::tls_record_application_data, message, ec);
        tampered.back() ^= 0x80;
        const auto tamper_header = std::span<const std::uint8_t, 5>(tampered.data(), 5);
        static_cast<void>(tamper_reader.open(tamper_header, std::span(tampered).subspan(5), ec));
        expect_error(ec, boost::system::errc::bad_message, "TLS tamper returned wrong error");
    }
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

    constexpr std::array<std::uint16_t, 17> expected_ciphers{
        0x1301, 0x1303, 0x1302, 0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030, 0xc00a, 0xc009, 0xc013, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035};
    std::size_t position = 71;
    expect(read_test_u16(wire, position, "ClientHello cipher length missing") == expected_ciphers.size() * 2, "ClientHello cipher length mismatch");
    position += 2;
    for (const auto expected : expected_ciphers)
    {
        expect(read_test_u16(wire, position, "ClientHello cipher missing") == expected, "ClientHello cipher order mismatch");
        position += 2;
    }

    constexpr std::array<std::uint8_t, 2> expected_compression{1, 0};
    expect_bytes(test_subspan(wire, position, expected_compression.size(), "ClientHello compression missing"), expected_compression,
                 "ClientHello compression mismatch");
    position += 2;

    const auto extensions_length = read_test_u16(wire, position, "ClientHello extensions length missing");
    position += 2;
    expect(extensions_length == wire.size() - position, "ClientHello extensions length mismatch");

    constexpr std::array<std::uint16_t, 15> expected_extension_types{
        0x0000, 0x0017, 0xff01, 0x000a, 0x000b, 0x0023, 0x0010, 0x0005, 0x0022, 0x0033, 0x002b, 0x000d, 0x002d, 0x001c, 0xfe0d};
    std::array<std::span<const std::uint8_t>, expected_extension_types.size()> extension_data{};
    for (std::size_t index = 0; index != expected_extension_types.size(); ++index)
    {
        expect(read_test_u16(wire, position, "ClientHello extension type missing") == expected_extension_types[index],
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

    constexpr std::array<std::uint8_t, 14> expected_groups{
        0x00, 0x0c, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00, 0x01, 0x01};
    expect_bytes(extension_data[3], expected_groups, "ClientHello supported groups mismatch");

    constexpr std::array<std::uint8_t, 14> expected_alpn{
        0x00, 0x0c, 0x02, 'h', '2', 0x08, 'h', 't', 't', 'p', '/', '1', '.', '1'};
    expect_bytes(extension_data[6], expected_alpn, "ClientHello ALPN mismatch");

    expect(extension_data[1].empty() && extension_data[5].empty(), "ClientHello empty extension mismatch");
    constexpr std::array<std::uint8_t, 1> expected_renegotiation{0x00};
    expect_bytes(extension_data[2], expected_renegotiation, "ClientHello renegotiation extension mismatch");
    constexpr std::array<std::uint8_t, 2> expected_point_formats{0x01, 0x00};
    expect_bytes(extension_data[4], expected_point_formats, "ClientHello point formats mismatch");
    constexpr std::array<std::uint8_t, 5> expected_status_request{0x01, 0x00, 0x00, 0x00, 0x00};
    expect_bytes(extension_data[7], expected_status_request, "ClientHello status request mismatch");
    constexpr std::array<std::uint8_t, 10> expected_delegated_credentials{
        0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03};
    expect_bytes(extension_data[8], expected_delegated_credentials, "ClientHello delegated credentials mismatch");

    const auto key_share = extension_data[9];
    expect(key_share.size() == 107 && read_test_u16(key_share, 0, "ClientHello key share list missing") == 105,
           "ClientHello key share length mismatch");
    expect(read_test_u16(key_share, 2, "ClientHello X25519 group missing") == 0x001d &&
               read_test_u16(key_share, 4, "ClientHello X25519 length missing") == 32,
           "ClientHello X25519 key share mismatch");
    expect(read_test_u16(key_share, 38, "ClientHello P-256 group missing") == 0x0017 &&
               read_test_u16(key_share, 40, "ClientHello P-256 length missing") == 65 && key_share[42] == 0x04,
           "ClientHello P-256 key share mismatch");

    constexpr std::array<std::uint8_t, 5> expected_versions{0x04, 0x03, 0x04, 0x03, 0x03};
    expect_bytes(extension_data[10], expected_versions, "ClientHello supported versions mismatch");

    constexpr std::array<std::uint8_t, 24> expected_signatures{
        0x00, 0x16, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08, 0x04, 0x08, 0x05,
        0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x03, 0x02, 0x01};
    expect_bytes(extension_data[11], expected_signatures, "ClientHello signature algorithms mismatch");

    constexpr std::array<std::uint8_t, 2> expected_psk_modes{0x01, 0x01};
    expect_bytes(extension_data[12], expected_psk_modes, "ClientHello PSK mode mismatch");

    constexpr std::array<std::uint8_t, 2> expected_record_size_limit{0x40, 0x01};
    expect_bytes(extension_data[13], expected_record_size_limit, "ClientHello record size limit mismatch");

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
    config.destination = rv::vless::domain_address{"example.com"};
    config.destination_port = 443;

    const auto request = rv::vless::encode_tcp_request(config, ec);
    std::vector<std::uint8_t> expected_tcp{0x00};
    expected_tcp.insert(expected_tcp.end(), config.user_id.begin(), config.user_id.end());
    constexpr std::array<std::uint8_t, 3> vision_prefix{0x12, 0x0a, 0x10};
    expected_tcp.insert(expected_tcp.end(), vision_prefix.begin(), vision_prefix.end());
    constexpr std::string_view vision_flow = "xtls-rprx-vision";
    expected_tcp.insert(expected_tcp.end(), vision_flow.begin(), vision_flow.end());
    constexpr std::array<std::uint8_t, 5> tcp_destination_prefix{0x01, 0x01, 0xbb, 0x02, 0x0b};
    expected_tcp.insert(expected_tcp.end(), tcp_destination_prefix.begin(), tcp_destination_prefix.end());
    constexpr std::string_view domain = "example.com";
    expected_tcp.insert(expected_tcp.end(), domain.begin(), domain.end());
    expect(!ec && request == expected_tcp, "VLESS TCP Vision header mismatch");

    config.destination_port = 53;
    const auto udp_request = rv::vless::encode_udp_request(config, ec);
    std::vector<std::uint8_t> expected_udp{0x00};
    expected_udp.insert(expected_udp.end(), config.user_id.begin(), config.user_id.end());
    constexpr std::array<std::uint8_t, 6> udp_destination_prefix{0x00, 0x02, 0x00, 0x35, 0x02, 0x0b};
    expected_udp.insert(expected_udp.end(), udp_destination_prefix.begin(), udp_destination_prefix.end());
    expected_udp.insert(expected_udp.end(), domain.begin(), domain.end());
    expect(!ec && udp_request == expected_udp, "VLESS UDP header mismatch");

    config.destination = rv::vless::ipv4_address{{192, 0, 2, 1}};
    const auto ipv4_request = rv::vless::encode_udp_request(config, ec);
    expect(!ec, "VLESS IPv4 encoding failed");
    constexpr std::array<std::uint8_t, 7> expected_ipv4_suffix{0x00, 0x35, 0x01, 192, 0, 2, 1};
    expect(ipv4_request.size() >= expected_ipv4_suffix.size() &&
               std::equal(expected_ipv4_suffix.begin(), expected_ipv4_suffix.end(), ipv4_request.end() - expected_ipv4_suffix.size()),
           "VLESS IPv4 address mismatch");

    config.destination = rv::vless::ipv6_address{{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}};
    config.destination_port = 443;
    const auto ipv6_request = rv::vless::encode_udp_request(config, ec);
    expect(!ec, "VLESS IPv6 encoding failed");
    constexpr std::array<std::uint8_t, 19> expected_ipv6_suffix{
        0x01, 0xbb, 0x03, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    expect(ipv6_request.size() >= expected_ipv6_suffix.size() &&
               std::equal(expected_ipv6_suffix.begin(), expected_ipv6_suffix.end(), ipv6_request.end() - expected_ipv6_suffix.size()),
           "VLESS IPv6 address mismatch");

    config.destination = rv::vless::domain_address{};
    static_cast<void>(rv::vless::encode_tcp_request(config, ec));
    expect_error(ec, boost::system::errc::invalid_argument, "VLESS empty domain returned wrong error");

    config.destination = rv::vless::domain_address{std::string("bad\0domain", 10)};
    static_cast<void>(rv::vless::encode_tcp_request(config, ec));
    expect_error(ec, boost::system::errc::invalid_argument, "VLESS embedded NUL domain returned wrong error");

    config.destination = rv::vless::domain_address{std::string(255, 'a')};
    const auto maximum_domain_request = rv::vless::encode_tcp_request(config, ec);
    expect(!ec && !maximum_domain_request.empty(), "VLESS maximum domain length rejected");

    config.destination = rv::vless::domain_address{std::string(256, 'a')};
    static_cast<void>(rv::vless::encode_tcp_request(config, ec));
    expect_error(ec, boost::system::errc::invalid_argument, "VLESS oversized domain returned wrong error");

    config.destination = rv::vless::domain_address{"example.com"};
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
    body.push_back(0x00);
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
    constexpr std::string_view http_request = "GET / HTTP/1.1\r\nHoSt: example.com:443\r\nUser-Agent: test\r\n\r\n";
    auto result = rv::sniff::inspect_destination(std::span(reinterpret_cast<const std::uint8_t*>(http_request.data()), 2));
    expect(result.state == rv::sniff::status::need_more, "destination sniffer rejected a fragmented HTTP method");

    result = rv::sniff::inspect_destination(
        std::span(reinterpret_cast<const std::uint8_t*>(http_request.data()), http_request.size()));
    expect(result.state == rv::sniff::status::found && result.domain == "example.com", "destination sniffer missed HTTP Host");

    const auto tls_client_hello = make_test_tls_client_hello("example.com");
    for (std::size_t size = 1; size != tls_client_hello.size(); ++size)
    {
        result = rv::sniff::inspect_destination(std::span(tls_client_hello).first(size));
        expect(result.state == rv::sniff::status::need_more, "destination sniffer rejected fragmented TLS ClientHello");
    }
    result = rv::sniff::inspect_destination(tls_client_hello);
    expect(result.state == rv::sniff::status::found && result.domain == "example.com", "destination sniffer missed TLS SNI");

    constexpr std::string_view ssh_banner = "SSH-2.0-test\r\n";
    result = rv::sniff::inspect_destination(
        std::span(reinterpret_cast<const std::uint8_t*>(ssh_banner.data()), ssh_banner.size()));
    expect(result.state == rv::sniff::status::no_match, "destination sniffer accepted an unrelated protocol");
}

void test_vision_frame_codec()
{
    boost::system::error_code ec;
    std::array<std::uint8_t, rv::vision::user_id_size> user_id{};
    user_id.fill(0x42);
    constexpr std::array<std::uint8_t, 4> content{1, 2, 3, 4};

    const auto frame = rv::vision::encode_frame(
        rv::vision::command::end_padding, std::span<const std::uint8_t, rv::vision::user_id_size>(user_id), content, false, ec);
    expect(!ec && frame.size() >= rv::vision::full_header_size + content.size() && frame.size() <= rv::vision::xray_buffer_size,
           "Vision full frame encode failed");

    rv::vision::frame_header header;
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(frame.data(), rv::vision::full_header_size), true, user_id, header);
    expect(!ec, "Vision full header decode failed");
    expect(header.frame_command == rv::vision::command::end_padding, "Vision full header command mismatch");
    expect(header.content_length == content.size(), "Vision full header content length mismatch");
    expect(frame.size() == rv::vision::full_header_size + header.content_length + header.padding_length,
           "Vision full frame length mismatch");
    expect(header.padding_length <= 255, "Vision short padding length mismatch");
    const auto padding = std::span(frame).subspan(rv::vision::full_header_size + header.content_length);
    expect(std::all_of(padding.begin(), padding.end(), [](const std::uint8_t byte) { return byte == 0; }),
           "Vision padding contains non-zero data");

    auto wrong_user = user_id;
    wrong_user[0] ^= 1;
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(frame.data(), rv::vision::full_header_size), true, wrong_user, header);
    expect_error(ec, boost::system::errc::permission_denied, "Vision wrong user returned wrong error");

    for (const auto frame_command :
         std::array{rv::vision::command::continue_padding, rv::vision::command::end_padding, rv::vision::command::direct})
    {
        auto header_bytes = std::array<std::uint8_t, rv::vision::short_header_size>{};
        header_bytes[0] = static_cast<std::uint8_t>(frame_command);
        ec = rv::vision::decode_header(header_bytes, false, user_id, header);
        expect(!ec && header.frame_command == frame_command, "Vision command decode mismatch");
    }

    ec.clear();
    const auto short_frame = rv::vision::encode_frame(rv::vision::command::direct, std::nullopt, content, false, ec);
    expect(!ec && short_frame.size() >= rv::vision::short_header_size + content.size(), "Vision short frame encode failed");
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(short_frame.data(), rv::vision::short_header_size), false, user_id, header);
    expect(!ec && header.frame_command == rv::vision::command::direct && header.content_length == content.size(),
           "Vision short header decode mismatch");

    constexpr std::array<std::uint8_t, rv::vision::short_header_size> invalid_command{0x03, 0x00, 0x00, 0x00, 0x00};
    ec = rv::vision::decode_header(invalid_command, false, user_id, header);
    expect_error(ec, boost::system::errc::bad_message, "Vision invalid command returned wrong error");

    constexpr std::array<std::uint8_t, rv::vision::short_header_size> oversized_header{0x00, 0x1f, 0xfe, 0x00, 0x00};
    ec = rv::vision::decode_header(oversized_header, false, user_id, header);
    expect_error(ec, boost::system::errc::message_size, "Vision oversized frame header returned wrong error");

    const std::vector<std::uint8_t> oversized_content(rv::vision::xray_buffer_size - rv::vision::short_header_size + 1, 0x55);
    ec.clear();
    static_cast<void>(rv::vision::encode_frame(rv::vision::command::continue_padding, std::nullopt, oversized_content, false, ec));
    expect_error(ec, boost::system::errc::message_size, "Vision encoder accepted oversized content");

    ec.clear();
    const auto long_padding_frame = rv::vision::encode_frame(
        rv::vision::command::continue_padding, std::span<const std::uint8_t, rv::vision::user_id_size>(user_id), content, true, ec);
    expect(!ec, "Vision long padding encode failed");
    ec = rv::vision::decode_header(
        std::span<const std::uint8_t>(long_padding_frame.data(), rv::vision::full_header_size), true, user_id, header);
    expect(!ec && header.padding_length >= 900 - content.size() && header.padding_length < 1400 - content.size(),
           "Vision long padding length mismatch");
}

void test_vision_tls_trackers()
{
    rv::vision::client_tls_record_tracker tracker;
    constexpr std::array<std::uint8_t, 9> client_hello{0x16, 0x03, 0x01, 0x00, 0x04, 0x01, 0x00, 0x00, 0x00};

    auto observation = tracker.observe(std::span(client_hello).first(2));
    expect(observation.kind == rv::vision::client_stream_kind::undecided, "TLS tracker decided too early");

    observation = tracker.observe(std::span(client_hello).subspan(2, 3));
    expect(observation.kind == rv::vision::client_stream_kind::undecided, "TLS tracker decided without payload");

    observation = tracker.observe(std::span(client_hello).subspan(5, 1));
    expect(observation.kind == rv::vision::client_stream_kind::tls, "TLS tracker missed fragmented ClientHello");

    observation = tracker.observe(std::span(client_hello).subspan(6));
    expect(!observation.encrypted_record_end_offset, "TLS tracker reported a handshake record as encrypted");

    constexpr std::array<std::uint8_t, 13> ccs_and_partial_encrypted{0x14, 0x03, 0x03, 0x00, 0x01, 0x01, 0x17, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb};
    observation = tracker.observe(ccs_and_partial_encrypted);
    expect(!observation.encrypted_record_end_offset, "TLS tracker accepted a partial encrypted record");

    constexpr std::array<std::uint8_t, 6> encrypted_tail_and_next_header{0xcc, 0xdd, 0x17, 0x03, 0x03, 0x00};
    observation = tracker.observe(encrypted_tail_and_next_header);
    expect(observation.encrypted_record_end_offset && *observation.encrypted_record_end_offset == 2,
           "TLS tracker returned the wrong cross-call record boundary");

    rv::vision::client_tls_record_tracker non_tls_tracker;
    constexpr std::array<std::uint8_t, 2> http_prefix{'G', 'E'};
    observation = non_tls_tracker.observe(http_prefix);
    expect(observation.kind == rv::vision::client_stream_kind::undecided, "TLS tracker rejected a short prefix too early");

    constexpr std::array<std::uint8_t, 3> http_suffix{'T', ' ', '/'};
    observation = non_tls_tracker.observe(http_suffix);
    expect(observation.kind == rv::vision::client_stream_kind::non_tls, "TLS tracker failed to classify HTTP");

    rv::vision::client_tls_record_tracker malformed_tracker;
    observation = malformed_tracker.observe(client_hello);
    expect(observation.kind == rv::vision::client_stream_kind::tls, "TLS tracker failed a complete ClientHello");

    constexpr std::array<std::uint8_t, 5> invalid_record_header{0x99, 0x03, 0x03, 0x00, 0x01};
    observation = malformed_tracker.observe(invalid_record_header);
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

    const auto fragmented_server_hello = make_test_tls_server_hello(0x1303, true);
    rv::vision::server_hello_tracker fragmented_tracker;
    constexpr std::array<std::uint8_t, 3> prefix{0xaa, 0xbb, 0xcc};
    fragmented_tracker.observe(prefix);
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

    constexpr std::array<std::uint8_t, 10> ipv4_request{5, 1, 0, 1, 127, 0, 0, 1, 0x01, 0xbb};
    ec = rv::socks5::decode_request(ipv4_request, request);
    expect(!ec, "SOCKS5 IPv4 CONNECT decode failed");
    expect(request.requested_command == rv::socks5::command::connect, "SOCKS5 CONNECT command mismatch");
    expect(request.port == 443, "SOCKS5 IPv4 CONNECT port mismatch");
    const auto* ipv4 = std::get_if<rv::socks5::ipv4_address>(&request.destination);
    expect(ipv4 != nullptr && ipv4->bytes == std::array<std::uint8_t, 4>{127, 0, 0, 1}, "SOCKS5 IPv4 CONNECT address mismatch");

    constexpr std::array<std::uint8_t, 18> domain_request{
        5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 0x01, 0xbb,
    };
    ec = rv::socks5::decode_request(domain_request, request);
    expect(!ec, "SOCKS5 domain CONNECT decode failed");
    const auto* domain = std::get_if<rv::socks5::domain_address>(&request.destination);
    expect(domain != nullptr && domain->name == "example.com" && request.port == 443, "SOCKS5 domain CONNECT mismatch");

    constexpr std::array<std::uint8_t, 22> ipv6_request{
        5, 1, 0, 4,
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        0x01, 0xbb,
    };
    ec = rv::socks5::decode_request(ipv6_request, request);
    expect(!ec, "SOCKS5 IPv6 CONNECT decode failed");
    const auto* ipv6 = std::get_if<rv::socks5::ipv6_address>(&request.destination);
    constexpr std::array<std::uint8_t, 16> expected_ipv6{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    expect(ipv6 != nullptr && ipv6->bytes == expected_ipv6 && request.port == 443, "SOCKS5 IPv6 CONNECT mismatch");

    constexpr std::array<std::uint8_t, 10> associate{5, 3, 0, 1, 0, 0, 0, 0, 0, 0};
    ec = rv::socks5::decode_request(associate, request);
    expect(!ec, "SOCKS5 UDP ASSOCIATE decode failed");
    expect(request.requested_command == rv::socks5::command::udp_associate && request.port == 0,
           "SOCKS5 UDP ASSOCIATE command mismatch");

    auto malformed = ipv4_request;
    malformed[0] = 4;
    ec = rv::socks5::decode_request(malformed, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted wrong version");

    malformed = ipv4_request;
    malformed[2] = 1;
    ec = rv::socks5::decode_request(malformed, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted nonzero reserved byte");

    malformed = ipv4_request;
    malformed[1] = 2;
    ec = rv::socks5::decode_request(malformed, request);
    expect_error(ec, boost::system::errc::operation_not_supported, "SOCKS5 unsupported command returned wrong error");

    malformed = ipv4_request;
    malformed[3] = 2;
    ec = rv::socks5::decode_request(malformed, request);
    expect_error(ec, boost::system::errc::address_family_not_supported, "SOCKS5 unsupported address type returned wrong error");

    constexpr std::array<std::uint8_t, 9> truncated_ipv4{5, 1, 0, 1, 127, 0, 0, 1, 0x01};
    ec = rv::socks5::decode_request(truncated_ipv4, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted truncated IPv4 request");

    constexpr std::array<std::uint8_t, 7> empty_domain{5, 1, 0, 3, 0, 0, 80};
    ec = rv::socks5::decode_request(empty_domain, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted empty domain");

    constexpr std::array<std::uint8_t, 10> nul_domain{5, 1, 0, 3, 3, 'a', 0, 'b', 0, 80};
    ec = rv::socks5::decode_request(nul_domain, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted domain containing NUL");

    constexpr std::array<std::uint8_t, 11> trailing_bytes{5, 1, 0, 1, 127, 0, 0, 1, 0, 80, 0};
    ec = rv::socks5::decode_request(trailing_bytes, request);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 accepted trailing request bytes");

    constexpr std::array<std::uint8_t, 10> zero_connect_port{5, 1, 0, 1, 127, 0, 0, 1, 0, 0};
    ec = rv::socks5::decode_request(zero_connect_port, request);
    expect_error(ec, boost::system::errc::invalid_argument, "SOCKS5 CONNECT accepted port zero");
}

void test_socks5_udp_codec()
{
    boost::system::error_code ec;
    rv::socks5::udp_datagram datagram;

    constexpr std::array<std::uint8_t, 13> ipv4_packet{0, 0, 0, 1, 8, 8, 8, 8, 0, 53, 'd', 'n', 's'};
    ec = rv::socks5::decode_udp_datagram(ipv4_packet, datagram);
    expect(!ec && datagram.port == 53 && datagram.payload.size() == 3, "SOCKS5 IPv4 UDP datagram decode failed");
    const auto encoded_ipv4 = rv::socks5::encode_udp_datagram(datagram.destination, datagram.port, datagram.payload, ec);
    expect(!ec && encoded_ipv4 == std::vector<std::uint8_t>(ipv4_packet.begin(), ipv4_packet.end()), "SOCKS5 IPv4 UDP roundtrip mismatch");

    constexpr std::array<std::uint8_t, 12> domain_packet{0, 0, 0, 3, 3, 'd', 'n', 's', 0, 53, 0xaa, 0xbb};
    ec = rv::socks5::decode_udp_datagram(domain_packet, datagram);
    expect(!ec && datagram.port == 53 && datagram.payload.size() == 2, "SOCKS5 domain UDP datagram decode failed");
    const auto* domain = std::get_if<rv::socks5::domain_address>(&datagram.destination);
    expect(domain != nullptr && domain->name == "dns", "SOCKS5 domain UDP destination mismatch");

    constexpr std::array<std::uint8_t, 25> ipv6_packet{
        0, 0, 0, 4,
        0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88,
        0, 53, 1, 2, 3,
    };
    ec = rv::socks5::decode_udp_datagram(ipv6_packet, datagram);
    expect(!ec && datagram.port == 53 && datagram.payload.size() == 3, "SOCKS5 IPv6 UDP datagram decode failed");
    const auto encoded_ipv6 = rv::socks5::encode_udp_datagram(datagram.destination, datagram.port, datagram.payload, ec);
    expect(!ec && encoded_ipv6 == std::vector<std::uint8_t>(ipv6_packet.begin(), ipv6_packet.end()), "SOCKS5 IPv6 UDP roundtrip mismatch");

    auto malformed = ipv4_packet;
    malformed[0] = 1;
    ec = rv::socks5::decode_udp_datagram(malformed, datagram);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 UDP accepted nonzero reserved field");

    malformed = ipv4_packet;
    malformed[2] = 1;
    ec = rv::socks5::decode_udp_datagram(malformed, datagram);
    expect_error(ec, boost::system::errc::operation_not_supported, "SOCKS5 UDP fragmentation returned wrong error");

    malformed = ipv4_packet;
    malformed[3] = 2;
    ec = rv::socks5::decode_udp_datagram(malformed, datagram);
    expect_error(ec, boost::system::errc::address_family_not_supported, "SOCKS5 UDP unsupported address type returned wrong error");

    constexpr std::array<std::uint8_t, 9> truncated_ipv4{0, 0, 0, 1, 8, 8, 8, 8, 0};
    ec = rv::socks5::decode_udp_datagram(truncated_ipv4, datagram);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 UDP accepted truncated datagram");

    constexpr std::array<std::uint8_t, 10> zero_port{0, 0, 0, 1, 8, 8, 8, 8, 0, 0};
    ec = rv::socks5::decode_udp_datagram(zero_port, datagram);
    expect_error(ec, boost::system::errc::invalid_argument, "SOCKS5 UDP accepted port zero");

    constexpr std::array<std::uint8_t, 10> nul_domain{0, 0, 0, 3, 3, 'a', 0, 'b', 0, 53};
    ec = rv::socks5::decode_udp_datagram(nul_domain, datagram);
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 UDP accepted domain containing NUL");

    const rv::socks5::domain_address invalid_domain{std::string("a\0b", 3)};
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
        std::pair{"HKDF", &test_hkdf_rfc5869},
        std::pair{"TLS records", &test_record_roundtrip},
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

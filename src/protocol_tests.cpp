#include "protocol_tests.hpp"

#include "base64.hpp"
#include "byte_queue.hpp"
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
    expect(hello->handshake_bytes.size() > 100 && hello->handshake_bytes[0] == 1, "ClientHello wire mismatch");
    expect(std::equal(hello->session_id.begin(), hello->session_id.end(), hello->handshake_bytes.begin() + 39), "ClientHello session ID mismatch");
}

void test_vless_header()
{
    boost::system::error_code ec;
    rv::vless::client_config config;
    config.user_id.fill(0x11);
    config.destination = rv::vless::domain_address{"example.com"};
    config.destination_port = 443;
    const auto request = rv::vless::encode_tcp_request(config, ec);
    expect(!ec && !request.empty(), "VLESS request encoding failed");

    config.destination = rv::vless::domain_address{};
    static_cast<void>(rv::vless::encode_tcp_request(config, ec));
    expect_error(ec, boost::system::errc::invalid_argument, "VLESS invalid domain returned wrong error");
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

void test_vision_codec()
{
    boost::system::error_code ec;
    std::array<std::uint8_t, rv::vision::user_id_size> user_id{};
    user_id.fill(0x42);
    constexpr std::array<std::uint8_t, 4> content{1, 2, 3, 4};
    const auto frame = rv::vision::encode_frame(
        rv::vision::command::end_padding, std::span<const std::uint8_t, rv::vision::user_id_size>(user_id), content, false, ec);
    expect(!ec && frame.size() >= rv::vision::full_header_size + content.size(), "Vision encode failed");

    rv::vision::frame_header header;
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(frame.data(), rv::vision::full_header_size), true, user_id, header);
    expect(!ec, "Vision decode failed");
    expect(header.content_length == content.size(), "Vision content length mismatch");

    auto wrong_user = user_id;
    wrong_user[0] ^= 1;
    ec = rv::vision::decode_header(std::span<const std::uint8_t>(frame.data(), rv::vision::full_header_size), true, wrong_user, header);
    expect_error(ec, boost::system::errc::permission_denied, "Vision wrong user returned wrong error");

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
}

void test_socks5_decode()
{
    boost::system::error_code ec;
    constexpr std::array<std::uint8_t, 10> wire{5, 1, 0, 1, 127, 0, 0, 1, 0x01, 0xbb};
    rv::socks5::connect_request request;
    ec = rv::socks5::decode_connect_request(wire, request);
    expect(!ec, "SOCKS5 decode failed");
    expect(request.port == 443, "SOCKS5 port mismatch");

    auto malformed = wire;
    malformed[0] = 4;
    ec = rv::socks5::decode_connect_request(malformed, request);
    expect(static_cast<bool>(ec), "SOCKS5 accepted wrong version");
    expect_error(ec, boost::system::errc::bad_message, "SOCKS5 malformed request returned wrong error");
}

}    // namespace

int run_protocol_tests()
{
    const std::array tests{
        std::pair{"text codecs", &test_text_codecs},
        std::pair{"byte queue", &test_byte_queue},
        std::pair{"HKDF", &test_hkdf_rfc5869},
        std::pair{"TLS records", &test_record_roundtrip},
        std::pair{"ClientHello", &test_client_hello},
        std::pair{"VLESS header", &test_vless_header},
        std::pair{"destination sniffer", &test_destination_sniffer},
        std::pair{"Vision codec", &test_vision_codec},
        std::pair{"SOCKS5 decode", &test_socks5_decode},
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

#include "sniffer.hpp"

#include "byte_order.hpp"
#include "byte_reader.hpp"
#include "tls_constants.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>

namespace rv::sniff
{
namespace
{


[[nodiscard]] result make_result(const status state, std::string domain = {})
{
    return {.state = state, .domain = std::move(domain)};
}

[[nodiscard]] bool is_valid_domain(const std::span<const std::uint8_t> input) noexcept
{
    if (input.empty() || input.size() > 255)
    {
        return false;
    }

    return std::ranges::all_of(
        input,
        [](const std::uint8_t value)
        {
            return value > 0x20 && value < 0x7f && value != ':' && value != '/' && value != '\\';
        });
}

[[nodiscard]] std::optional<std::string> parse_server_name(const std::span<const std::uint8_t> extension)
{
    core::byte_reader reader(extension);
    std::uint16_t list_size = 0;
    if (!reader.read_u16(list_size) || reader.remaining() != list_size)
    {
        return std::nullopt;
    }

    while (reader.remaining() != 0)
    {
        std::uint8_t name_type = 0;
        std::uint16_t name_size = 0;
        if (!reader.read_u8(name_type) || !reader.read_u16(name_size))
        {
            return std::nullopt;
        }
        const auto name = reader.read_bytes(name_size);
        if (!name)
        {
            return std::nullopt;
        }
        if (name_type == 0 && is_valid_domain(*name))
        {
            return std::string(reinterpret_cast<const char*>(name->data()), name->size());
        }
    }

    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> find_server_name(const std::span<const std::uint8_t> extensions)
{
    core::byte_reader reader(extensions);
    while (reader.remaining() != 0)
    {
        std::uint16_t type = 0;
        std::uint16_t size = 0;
        if (!reader.read_u16(type) || !reader.read_u16(size))
        {
            return std::nullopt;
        }
        const auto extension = reader.read_bytes(size);
        if (!extension)
        {
            return std::nullopt;
        }
        if (type == tls::kExtensionServerName)
        {
            return parse_server_name(*extension);
        }
    }
    return std::nullopt;
}

[[nodiscard]] std::optional<std::string> parse_client_hello(const std::span<const std::uint8_t> handshake)
{
    if (handshake.size() < tls::kHandshakeHeaderSize || handshake[0] != tls::kHandshakeClientHello)
    {
        return std::nullopt;
    }

    const auto body_size = static_cast<std::size_t>(core::read_be24(handshake.data() + 1));
    if (handshake.size() < tls::kHandshakeHeaderSize + body_size)
    {
        return std::nullopt;
    }

    core::byte_reader reader(handshake.subspan(tls::kHandshakeHeaderSize, body_size));
    if (!reader.skip(2 + 32))
    {
        return std::nullopt;
    }

    std::uint8_t session_id_size = 0;
    if (!reader.read_u8(session_id_size) || !reader.skip(session_id_size))
    {
        return std::nullopt;
    }

    std::uint16_t cipher_suites_size = 0;
    if (!reader.read_u16(cipher_suites_size) || !reader.skip(cipher_suites_size))
    {
        return std::nullopt;
    }

    std::uint8_t compression_methods_size = 0;
    if (!reader.read_u8(compression_methods_size) || !reader.skip(compression_methods_size))
    {
        return std::nullopt;
    }

    std::uint16_t extensions_size = 0;
    if (!reader.read_u16(extensions_size))
    {
        return std::nullopt;
    }
    const auto extensions = reader.read_bytes(extensions_size);
    if (!extensions)
    {
        return std::nullopt;
    }
    return find_server_name(*extensions);
}

[[nodiscard]] result sniff_tls(const std::span<const std::uint8_t> input)
{
    if (input.size() < tls::kRecordHeaderSize)
    {
        return make_result(status::kNeedMore);
    }
    if (input[0] != tls::kRecordHandshake || input[1] != 0x03 || input[2] > 0x03)
    {
        return make_result(status::kNoMatch);
    }

    const auto payload_size = static_cast<std::size_t>(core::read_be16(input.data() + 3));
    if (payload_size == 0 || payload_size > tls::kMaximumPlaintextSize)
    {
        return make_result(status::kNoMatch);
    }
    if (input.size() < tls::kRecordHeaderSize + payload_size)
    {
        return make_result(status::kNeedMore);
    }

    const auto domain = parse_client_hello(input.subspan(tls::kRecordHeaderSize, payload_size));
    if (!domain)
    {
        return make_result(status::kNoMatch);
    }
    return make_result(status::kFound, *domain);
}

[[nodiscard]] bool is_http_method_prefix(const std::string_view input, bool& complete) noexcept
{
    constexpr std::array<std::string_view, 9> kMethods{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE "};

    complete = false;
    for (const auto method : kMethods)
    {
        const auto compared_size = std::min(input.size(), method.size());
        if (input.substr(0, compared_size) != method.substr(0, compared_size))
        {
            continue;
        }
        complete = input.size() >= method.size();
        return true;
    }
    return false;
}

[[nodiscard]] bool equals_ascii_case_insensitive(const std::string_view lhs, const std::string_view rhs) noexcept
{
    if (lhs.size() != rhs.size())
    {
        return false;
    }

    for (std::size_t index = 0; index != lhs.size(); ++index)
    {
        auto left = static_cast<unsigned char>(lhs[index]);
        auto right = static_cast<unsigned char>(rhs[index]);
        if (left >= 'A' && left <= 'Z')
        {
            left = static_cast<unsigned char>(left - 'A' + 'a');
        }
        if (right >= 'A' && right <= 'Z')
        {
            right = static_cast<unsigned char>(right - 'A' + 'a');
        }
        if (left != right)
        {
            return false;
        }
    }
    return true;
}

[[nodiscard]] std::string_view trim_http_whitespace(std::string_view input) noexcept
{
    while (!input.empty() && (input.front() == ' ' || input.front() == '\t'))
    {
        input.remove_prefix(1);
    }
    while (!input.empty() && (input.back() == ' ' || input.back() == '\t'))
    {
        input.remove_suffix(1);
    }
    return input;
}

[[nodiscard]] std::optional<std::string> parse_http_host(std::string_view host)
{
    host = trim_http_whitespace(host);
    if (host.empty() || host.front() == '[')
    {
        return std::nullopt;
    }

    const auto colon = host.rfind(':');
    if (colon != std::string_view::npos && host.find(':') == colon)
    {
        const auto port = host.substr(colon + 1);
        if (!port.empty() && std::ranges::all_of(port, [](const char value) { return value >= '0' && value <= '9'; }))
        {
            host = host.substr(0, colon);
        }
    }
    if (host.find(':') != std::string_view::npos)
    {
        return std::nullopt;
    }

    const auto bytes = std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(host.data()), host.size());
    if (!is_valid_domain(bytes))
    {
        return std::nullopt;
    }
    return std::string(host);
}

[[nodiscard]] result sniff_http(const std::span<const std::uint8_t> input)
{
    using namespace std::string_view_literals;

    const std::string_view text(reinterpret_cast<const char*>(input.data()), input.size());
    bool method_complete = false;
    if (!is_http_method_prefix(text, method_complete))
    {
        return make_result(status::kNoMatch);
    }
    if (!method_complete)
    {
        return make_result(status::kNeedMore);
    }

    const auto request_line_end = text.find("\r\n");
    if (request_line_end == std::string_view::npos)
    {
        return make_result(status::kNeedMore);
    }

    std::size_t offset = request_line_end + 2;
    for (;;)
    {
        const auto line_end = text.find("\r\n", offset);
        if (line_end == std::string_view::npos)
        {
            return make_result(status::kNeedMore);
        }
        const auto line = text.substr(offset, line_end - offset);
        if (line.empty())
        {
            return make_result(status::kNoMatch);
        }

        const auto colon = line.find(':');
        if (colon != std::string_view::npos && equals_ascii_case_insensitive(trim_http_whitespace(line.substr(0, colon)), "host"sv))
        {
            const auto domain = parse_http_host(line.substr(colon + 1));
            return domain ? make_result(status::kFound, *domain) : make_result(status::kNoMatch);
        }
        offset = line_end + 2;
    }
}

}    // namespace

result inspect_destination(const std::span<const std::uint8_t> input)
{
    if (input.empty())
    {
        return make_result(status::kNeedMore);
    }
    if (input[0] == tls::kRecordHandshake)
    {
        return sniff_tls(input);
    }
    return sniff_http(input);
}

}    // namespace rv::sniff

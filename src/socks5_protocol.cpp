#include "socks5_protocol.hpp"

#include "byte_order.hpp"
#include "byte_writer.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/ip/address_v6.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

namespace rv::socks5
{
namespace asio = boost::asio;
namespace
{

constexpr std::uint8_t kVersion = 0x05;
constexpr std::uint8_t kNoAuthentication = 0x00;
constexpr std::uint8_t kUsernamePasswordAuthentication = 0x02;
constexpr std::uint8_t kNoAcceptableMethod = 0xff;
constexpr std::uint8_t kAuthenticationVersion = 0x01;
constexpr std::uint8_t kBindCommand = 0x02;
constexpr std::uint8_t kIpv4Type = 0x01;
constexpr std::uint8_t kDomainType = 0x03;
constexpr std::uint8_t kIpv6Type = 0x04;

asio::awaitable<void> read_exact(asio::ip::tcp::socket& socket, std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    co_await asio::async_read(socket, asio::buffer(output.data(), output.size()), asio::redirect_error(asio::use_awaitable, ec));
}

asio::awaitable<void> write_all(asio::ip::tcp::socket& socket, std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    co_await asio::async_write(socket, asio::buffer(input.data(), input.size()), asio::redirect_error(asio::use_awaitable, ec));
}

boost::system::error_code decode_address(const std::span<const std::uint8_t> input,
                                         const std::size_t type_offset,
                                         address& destination,
                                         std::size_t& next_offset)
{
    using boost::system::errc::make_error_code;

    if (type_offset >= input.size())
    {
        return make_error_code(boost::system::errc::bad_message);
    }

    switch (input[type_offset])
    {
        case kIpv4Type:
        {
            constexpr std::size_t kAddressSize = 4;
            const auto begin = type_offset + 1;
            if (input.size() < begin + kAddressSize)
            {
                return make_error_code(boost::system::errc::bad_message);
            }
            ipv4_address ipv4;
            std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(begin), ipv4.bytes.size(), ipv4.bytes.begin());
            destination = ipv4;
            next_offset = begin + kAddressSize;
            return {};
        }
        case kDomainType:
        {
            const auto length_offset = type_offset + 1;
            if (length_offset >= input.size())
            {
                return make_error_code(boost::system::errc::bad_message);
            }
            const auto domain_length = static_cast<std::size_t>(input[length_offset]);
            const auto begin = length_offset + 1;
            if (domain_length == 0 || input.size() < begin + domain_length)
            {
                return make_error_code(boost::system::errc::bad_message);
            }

            const auto domain = input.subspan(begin, domain_length);
            if (std::ranges::find(domain, std::uint8_t{0}) != domain.end())
            {
                return make_error_code(boost::system::errc::bad_message);
            }

            destination = domain_address{std::string(reinterpret_cast<const char*>(domain.data()), domain.size())};
            next_offset = begin + domain_length;
            return {};
        }
        case kIpv6Type:
        {
            constexpr std::size_t kAddressSize = 16;
            const auto begin = type_offset + 1;
            if (input.size() < begin + kAddressSize)
            {
                return make_error_code(boost::system::errc::bad_message);
            }
            ipv6_address ipv6;
            std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(begin), ipv6.bytes.size(), ipv6.bytes.begin());
            destination = ipv6;
            next_offset = begin + kAddressSize;
            return {};
        }
        default:
            return make_error_code(boost::system::errc::address_family_not_supported);
    }
}

void encode_address(const address& source, std::vector<std::uint8_t>& output, boost::system::error_code& ec)
{
    std::visit(
        [&output, &ec](const auto& value)
        {
            using address_type = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<address_type, ipv4_address>)
            {
                output.push_back(kIpv4Type);
                output.insert(output.end(), value.bytes.begin(), value.bytes.end());
            }
            else if constexpr (std::is_same_v<address_type, ipv6_address>)
            {
                output.push_back(kIpv6Type);
                output.insert(output.end(), value.bytes.begin(), value.bytes.end());
            }
            else
            {
                if (value.name.empty() || value.name.size() > 255 || value.name.find('\0') != std::string::npos)
                {
                    ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
                    return;
                }
                output.push_back(kDomainType);
                output.push_back(static_cast<std::uint8_t>(value.name.size()));
                output.insert(output.end(), value.name.begin(), value.name.end());
            }
        },
        source);
}

asio::awaitable<void> authenticate_username_password(asio::ip::tcp::socket& socket, const credentials& expected, boost::system::error_code& ec)
{
    std::array<std::uint8_t, 2> header{};
    co_await read_exact(socket, header, ec);
    if (ec)
    {
        co_return;
    }
    if (header[0] != kAuthenticationVersion || header[1] == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }

    std::string username(header[1], '\0');
    co_await read_exact(socket, std::span(reinterpret_cast<std::uint8_t*>(username.data()), username.size()), ec);
    if (ec)
    {
        co_return;
    }

    std::array<std::uint8_t, 1> password_length{};
    co_await read_exact(socket, password_length, ec);
    if (ec)
    {
        co_return;
    }
    if (password_length[0] == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }

    std::string password(password_length[0], '\0');
    co_await read_exact(socket, std::span(reinterpret_cast<std::uint8_t*>(password.data()), password.size()), ec);
    if (ec)
    {
        co_return;
    }

    const bool authenticated = username == expected.username && password == expected.password;
    const std::array<std::uint8_t, 2> response{
        kAuthenticationVersion,
        static_cast<std::uint8_t>(authenticated ? 0x00 : 0x01),
    };
    co_await write_all(socket, response, ec);
    if (ec)
    {
        co_return;
    }
    if (!authenticated)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
    }
}

asio::awaitable<void> negotiate_authentication(asio::ip::tcp::socket& socket,
                                               const std::optional<credentials>& expected_credentials,
                                               boost::system::error_code& ec)
{
    std::array<std::uint8_t, 2> greeting{};
    co_await read_exact(socket, greeting, ec);
    if (ec)
    {
        co_return;
    }
    if (greeting[0] != kVersion)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        co_return;
    }

    std::vector<std::uint8_t> methods(greeting[1]);
    co_await read_exact(socket, methods, ec);
    if (ec)
    {
        co_return;
    }

    const auto selected_method = expected_credentials ? kUsernamePasswordAuthentication : kNoAuthentication;
    const bool supported = std::ranges::find(methods, selected_method) != methods.end();
    const std::array<std::uint8_t, 2> selection{
        kVersion,
        supported ? selected_method : kNoAcceptableMethod,
    };
    co_await write_all(socket, selection, ec);
    if (ec)
    {
        co_return;
    }
    if (!supported)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
        co_return;
    }

    if (expected_credentials)
    {
        co_await authenticate_username_password(socket, *expected_credentials, ec);
    }
}

asio::awaitable<void> send_reply_ignoring_error(asio::ip::tcp::socket& socket, const reply value)
{
    boost::system::error_code ignored;
    co_await send_reply(socket, value, ignored);
}

asio::awaitable<void> read_request_header(asio::ip::tcp::socket& socket, std::array<std::uint8_t, 4>& header, boost::system::error_code& ec)
{
    co_await read_exact(socket, header, ec);
    if (ec)
    {
        co_return;
    }
    if (header[0] != kVersion || header[2] != 0)
    {
        co_await send_reply_ignoring_error(socket, reply::kGeneralFailure);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }
    if (header[1] == kBindCommand || (header[1] != static_cast<std::uint8_t>(command::kConnect) &&
                                      header[1] != static_cast<std::uint8_t>(command::kUdpAssociate)))
    {
        co_await send_reply_ignoring_error(socket, reply::kCommandNotSupported);
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
    }
}

asio::awaitable<void> read_request_body(asio::ip::tcp::socket& socket,
                                        const std::array<std::uint8_t, 4>& header,
                                        std::vector<std::uint8_t>& request_bytes,
                                        boost::system::error_code& ec)
{
    switch (header[3])
    {
        case kIpv4Type:
        {
            const auto offset = request_bytes.size();
            request_bytes.resize(offset + 6);
            co_await read_exact(socket, std::span(request_bytes).subspan(offset), ec);
            break;
        }
        case kDomainType:
        {
            std::array<std::uint8_t, 1> domain_length{};
            co_await read_exact(socket, domain_length, ec);
            if (ec)
            {
                co_return;
            }
            if (domain_length[0] == 0)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return;
            }

            request_bytes.push_back(domain_length[0]);
            const auto offset = request_bytes.size();
            request_bytes.resize(offset + static_cast<std::size_t>(domain_length[0]) + 2);
            co_await read_exact(socket, std::span(request_bytes).subspan(offset), ec);
            break;
        }
        case kIpv6Type:
        {
            const auto offset = request_bytes.size();
            request_bytes.resize(offset + 18);
            co_await read_exact(socket, std::span(request_bytes).subspan(offset), ec);
            break;
        }
        default:
            co_await send_reply_ignoring_error(socket, reply::kAddressTypeNotSupported);
            ec = boost::system::errc::make_error_code(boost::system::errc::address_family_not_supported);
            co_return;
    }
}

asio::awaitable<std::optional<std::vector<std::uint8_t>>> read_request_bytes(asio::ip::tcp::socket& socket, boost::system::error_code& ec)
{
    std::array<std::uint8_t, 4> header{};
    co_await read_request_header(socket, header, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    std::vector<std::uint8_t> request_bytes(header.begin(), header.end());
    co_await read_request_body(socket, header, request_bytes, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_return request_bytes;
}

std::vector<std::uint8_t> encode_bound_reply(const reply value, const asio::ip::udp::endpoint& endpoint, boost::system::error_code& ec)
{
    ec.clear();
    if (!endpoint.address().is_v4())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::address_family_not_supported);
        return {};
    }

    const auto bytes = endpoint.address().to_v4().to_bytes();
    std::vector<std::uint8_t> output{
        kVersion,
        static_cast<std::uint8_t>(value),
        0x00,
        kIpv4Type,
    };
    output.insert(output.end(), bytes.begin(), bytes.end());
    core::append_be16(output, endpoint.port());
    return output;
}

}    // namespace

boost::system::error_code decode_request(const std::span<const std::uint8_t> request_bytes, request& output)
{
    using boost::system::errc::make_error_code;

    if (request_bytes.size() < 7 || request_bytes[0] != kVersion || request_bytes[2] != 0)
    {
        return make_error_code(boost::system::errc::bad_message);
    }

    command requested_command;
    switch (request_bytes[1])
    {
        case static_cast<std::uint8_t>(command::kConnect):
            requested_command = command::kConnect;
            break;
        case static_cast<std::uint8_t>(command::kUdpAssociate):
            requested_command = command::kUdpAssociate;
            break;
        default:
            return make_error_code(boost::system::errc::operation_not_supported);
    }

    address destination;
    std::size_t port_offset = 0;
    auto ec = decode_address(request_bytes, 3, destination, port_offset);
    if (ec)
    {
        return ec;
    }
    if (request_bytes.size() != port_offset + 2)
    {
        return make_error_code(boost::system::errc::bad_message);
    }

    const auto port = core::read_be16(request_bytes.data() + port_offset);
    if (requested_command == command::kConnect && port == 0)
    {
        return make_error_code(boost::system::errc::invalid_argument);
    }

    output = request{
        .requested_command = requested_command,
        .destination = std::move(destination),
        .port = port,
    };
    return {};
}

boost::system::error_code decode_udp_datagram(const std::span<const std::uint8_t> packet, udp_datagram& output)
{
    using boost::system::errc::make_error_code;

    if (packet.size() < 7 || packet[0] != 0 || packet[1] != 0)
    {
        return make_error_code(boost::system::errc::bad_message);
    }
    if (packet[2] != 0)
    {
        return make_error_code(boost::system::errc::operation_not_supported);
    }

    address destination;
    std::size_t port_offset = 0;
    auto ec = decode_address(packet, 3, destination, port_offset);
    if (ec)
    {
        return ec;
    }
    if (packet.size() < port_offset + 2)
    {
        return make_error_code(boost::system::errc::bad_message);
    }

    const auto port = core::read_be16(packet.data() + port_offset);
    if (port == 0)
    {
        return make_error_code(boost::system::errc::invalid_argument);
    }

    output = udp_datagram{
        .destination = std::move(destination),
        .port = port,
        .payload = packet.subspan(port_offset + 2),
    };
    return {};
}

std::array<std::uint8_t, 10> encode_reply(const reply value) noexcept
{
    return {
        kVersion,
        static_cast<std::uint8_t>(value),
        0x00,
        kIpv4Type,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };
}

std::vector<std::uint8_t> encode_udp_datagram(const address& source,
                                              const std::uint16_t port,
                                              const std::span<const std::uint8_t> payload,
                                              boost::system::error_code& ec)
{
    ec.clear();
    if (port == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    std::vector<std::uint8_t> output{0x00, 0x00, 0x00};
    output.reserve(payload.size() + 22);
    encode_address(source, output, ec);
    if (ec)
    {
        return {};
    }
    core::append_be16(output, port);
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

std::string format_destination(const address& destination, const std::uint16_t port)
{
    const auto host = std::visit(
        [](const auto& value) -> std::string
        {
            using address_type = std::decay_t<decltype(value)>;
            if constexpr (std::is_same_v<address_type, ipv4_address>)
            {
                return std::to_string(value.bytes[0]) + "." + std::to_string(value.bytes[1]) + "." + std::to_string(value.bytes[2]) + "." +
                       std::to_string(value.bytes[3]);
            }
            else if constexpr (std::is_same_v<address_type, ipv6_address>)
            {
                asio::ip::address_v6::bytes_type bytes{};
                std::copy(value.bytes.begin(), value.bytes.end(), bytes.begin());
                return "[" + asio::ip::address_v6(bytes).to_string() + "]";
            }
            else
            {
                return value.name;
            }
        },
        destination);
    return host + ":" + std::to_string(port);
}

std::string format_destination(const request& request) { return format_destination(request.destination, request.port); }

asio::awaitable<void> send_reply(asio::ip::tcp::socket& socket, const reply value, boost::system::error_code& ec)
{
    const auto reply_bytes = encode_reply(value);
    co_await write_all(socket, reply_bytes, ec);
}

asio::awaitable<void> send_reply(asio::ip::tcp::socket& socket,
                                 const reply value,
                                 const asio::ip::udp::endpoint& bound_endpoint,
                                 boost::system::error_code& ec)
{
    const auto reply_bytes = encode_bound_reply(value, bound_endpoint, ec);
    if (ec)
    {
        co_return;
    }
    co_await write_all(socket, reply_bytes, ec);
}

asio::awaitable<std::optional<request>> negotiate(asio::ip::tcp::socket& socket,
                                                   const std::optional<credentials>& expected_credentials,
                                                   boost::system::error_code& ec)
{
    co_await negotiate_authentication(socket, expected_credentials, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    auto request_bytes = co_await read_request_bytes(socket, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    request parsed;
    ec = decode_request(*request_bytes, parsed);
    if (ec)
    {
        co_await send_reply_ignoring_error(socket, reply::kGeneralFailure);
        co_return std::nullopt;
    }

    co_return parsed;
}

}    // namespace rv::socks5

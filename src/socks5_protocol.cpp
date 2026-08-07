#include "socks5_protocol.hpp"

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

constexpr std::uint8_t version = 0x05;
constexpr std::uint8_t no_authentication = 0x00;
constexpr std::uint8_t username_password_authentication = 0x02;
constexpr std::uint8_t no_acceptable_method = 0xff;
constexpr std::uint8_t authentication_version = 0x01;
constexpr std::uint8_t connect_command = 0x01;
constexpr std::uint8_t ipv4_type = 0x01;
constexpr std::uint8_t domain_type = 0x03;
constexpr std::uint8_t ipv6_type = 0x04;

asio::awaitable<void> read_exact(asio::ip::tcp::socket& socket, std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    co_await asio::async_read(socket, asio::buffer(output.data(), output.size()), asio::redirect_error(asio::use_awaitable, ec));
}

asio::awaitable<void> write_all(asio::ip::tcp::socket& socket, std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    co_await asio::async_write(socket, asio::buffer(input.data(), input.size()), asio::redirect_error(asio::use_awaitable, ec));
}

std::uint16_t read_port(const std::span<const std::uint8_t> request_bytes) noexcept
{
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(request_bytes[request_bytes.size() - 2]) << 8U |
                                      static_cast<std::uint16_t>(request_bytes.back()));
}

asio::awaitable<void> authenticate_username_password(asio::ip::tcp::socket& socket, const credentials& expected, boost::system::error_code& ec)
{
    std::array<std::uint8_t, 2> header{};
    co_await read_exact(socket, header, ec);
    if (ec)
    {
        co_return;
    }
    if (header[0] != authentication_version || header[1] == 0)
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
        authentication_version,
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
    if (greeting[0] != version)
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

    const auto selected_method = expected_credentials ? username_password_authentication : no_authentication;
    const bool supported = std::ranges::find(methods, selected_method) != methods.end();
    const std::array<std::uint8_t, 2> selection{
        version,
        supported ? selected_method : no_acceptable_method,
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

asio::awaitable<void> read_connect_request_header(asio::ip::tcp::socket& socket, std::array<std::uint8_t, 4>& header, boost::system::error_code& ec)
{
    co_await read_exact(socket, header, ec);
    if (ec)
    {
        co_return;
    }
    if (header[0] != version || header[2] != 0)
    {
        co_await send_reply_ignoring_error(socket, reply::general_failure);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return;
    }
    if (header[1] != connect_command)
    {
        co_await send_reply_ignoring_error(socket, reply::command_not_supported);
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
        co_return;
    }
    co_return;
}

asio::awaitable<void> read_connect_request_body(asio::ip::tcp::socket& socket,
                                                const std::array<std::uint8_t, 4>& header,
                                                std::vector<std::uint8_t>& request_bytes,
                                                boost::system::error_code& ec)
{
    switch (header[3])
    {
        case ipv4_type:
        {
            const auto offset = request_bytes.size();
            request_bytes.resize(offset + 6);
            co_await read_exact(socket, std::span(request_bytes).subspan(offset), ec);
            break;
        }
        case domain_type:
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
        case ipv6_type:
        {
            const auto offset = request_bytes.size();
            request_bytes.resize(offset + 18);
            co_await read_exact(socket, std::span(request_bytes).subspan(offset), ec);
            break;
        }
        default:
            co_await send_reply_ignoring_error(socket, reply::address_type_not_supported);
            ec = boost::system::errc::make_error_code(boost::system::errc::address_family_not_supported);
            co_return;
    }

    co_return;
}

asio::awaitable<std::optional<std::vector<std::uint8_t>>> read_connect_request_bytes(asio::ip::tcp::socket& socket, boost::system::error_code& ec)
{
    std::array<std::uint8_t, 4> header{};
    co_await read_connect_request_header(socket, header, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    std::vector<std::uint8_t> request_bytes(header.begin(), header.end());
    co_await read_connect_request_body(socket, header, request_bytes, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_return request_bytes;
}

boost::system::error_code decode_destination(const std::span<const std::uint8_t> request_bytes, address& destination)
{
    using boost::system::errc::make_error_code;

    switch (request_bytes[3])
    {
        case ipv4_type:
        {
            if (request_bytes.size() != 10)
            {
                return make_error_code(boost::system::errc::bad_message);
            }
            ipv4_address ipv4;
            std::copy_n(request_bytes.begin() + 4, ipv4.bytes.size(), ipv4.bytes.begin());
            destination = ipv4;
            return {};
        }
        case domain_type:
        {
            const auto domain_length = static_cast<std::size_t>(request_bytes[4]);
            if (domain_length == 0 || request_bytes.size() != 7 + domain_length)
            {
                return make_error_code(boost::system::errc::bad_message);
            }
            destination = domain_address{std::string(reinterpret_cast<const char*>(request_bytes.data() + 5), domain_length)};
            return {};
        }
        case ipv6_type:
        {
            if (request_bytes.size() != 22)
            {
                return make_error_code(boost::system::errc::bad_message);
            }
            ipv6_address ipv6;
            std::copy_n(request_bytes.begin() + 4, ipv6.bytes.size(), ipv6.bytes.begin());
            destination = ipv6;
            return {};
        }
        default:
            return make_error_code(boost::system::errc::address_family_not_supported);
    }
}

}    // namespace

boost::system::error_code decode_connect_request(const std::span<const std::uint8_t> request_bytes, connect_request& output)
{
    using boost::system::errc::make_error_code;

    if (request_bytes.size() < 7 || request_bytes[0] != version || request_bytes[2] != 0)
    {
        return make_error_code(boost::system::errc::bad_message);
    }
    if (request_bytes[1] != connect_command)
    {
        return make_error_code(boost::system::errc::operation_not_supported);
    }

    connect_request request;
    auto ec = decode_destination(request_bytes, request.destination);
    if (ec)
    {
        return ec;
    }

    request.port = read_port(request_bytes);
    if (request.port == 0)
    {
        return make_error_code(boost::system::errc::invalid_argument);
    }

    output = std::move(request);
    return {};
}

std::array<std::uint8_t, 10> encode_reply(const reply value) noexcept
{
    return {
        version,
        static_cast<std::uint8_t>(value),
        0x00,
        ipv4_type,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
        0x00,
    };
}

std::string format_destination(const connect_request& request)
{
    const auto host = std::visit(
        [](const auto& address) -> std::string
        {
            using address_type = std::decay_t<decltype(address)>;
            if constexpr (std::is_same_v<address_type, ipv4_address>)
            {
                return std::to_string(address.bytes[0]) + "." + std::to_string(address.bytes[1]) + "." + std::to_string(address.bytes[2]) + "." +
                       std::to_string(address.bytes[3]);
            }
            else if constexpr (std::is_same_v<address_type, ipv6_address>)
            {
                asio::ip::address_v6::bytes_type bytes{};
                std::copy(address.bytes.begin(), address.bytes.end(), bytes.begin());
                return "[" + asio::ip::address_v6(bytes).to_string() + "]";
            }
            else
            {
                return address.name;
            }
        },
        request.destination);
    return host + ":" + std::to_string(request.port);
}

asio::awaitable<void> send_reply(asio::ip::tcp::socket& socket, const reply value, boost::system::error_code& ec)
{
    const auto request_bytes = encode_reply(value);
    co_await write_all(socket, request_bytes, ec);
}

asio::awaitable<std::optional<connect_request>> negotiate_connect(asio::ip::tcp::socket& socket,
                                                                  const std::optional<credentials>& expected_credentials,
                                                                  boost::system::error_code& ec)
{
    co_await negotiate_authentication(socket, expected_credentials, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    auto request_bytes = co_await read_connect_request_bytes(socket, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    connect_request request;
    ec = decode_connect_request(*request_bytes, request);
    if (ec)
    {
        co_await send_reply_ignoring_error(socket, reply::general_failure);
        co_return std::nullopt;
    }

    co_return request;
}

}    // namespace rv::socks5

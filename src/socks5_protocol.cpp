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
    ec.clear();
    if (output.empty())
    {
        co_return;
    }
    co_await asio::async_read(socket, asio::buffer(output.data(), output.size()), asio::redirect_error(asio::use_awaitable, ec));
}

asio::awaitable<void> write_all(asio::ip::tcp::socket& socket, std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    ec.clear();
    if (input.empty())
    {
        co_return;
    }
    co_await asio::async_write(socket, asio::buffer(input.data(), input.size()), asio::redirect_error(asio::use_awaitable, ec));
}

std::uint16_t read_port(std::span<const std::uint8_t> wire) noexcept
{
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(wire[wire.size() - 2]) << 8U | static_cast<std::uint16_t>(wire.back()));
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
        constexpr std::array<std::uint8_t, 2> failure{authentication_version, 0x01};
        boost::system::error_code reply_ec;
        co_await write_all(socket, failure, reply_ec);
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
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
    std::string password(password_length[0], '\0');
    if (!password.empty())
    {
        co_await read_exact(socket, std::span(reinterpret_cast<std::uint8_t*>(password.data()), password.size()), ec);
        if (ec)
        {
            co_return;
        }
    }

    const bool authenticated = !password.empty() && username == expected.username && password == expected.password;
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

}    // namespace

bool decode_connect_request(std::span<const std::uint8_t> wire, connect_request& output, boost::system::error_code& ec)
{
    ec.clear();
    if (wire.size() < 7 || wire[0] != version || wire[2] != 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return false;
    }
    if (wire[1] != connect_command)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
        return false;
    }

    connect_request request;
    switch (wire[3])
    {
        case ipv4_type:
        {
            if (wire.size() != 10)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                return false;
            }
            ipv4_address address;
            std::copy_n(wire.begin() + 4, address.bytes.size(), address.bytes.begin());
            request.destination = address;
            break;
        }
        case domain_type:
        {
            const auto length = static_cast<std::size_t>(wire[4]);
            if (length == 0 || wire.size() != 7 + length)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                return false;
            }
            request.destination = domain_address{std::string(reinterpret_cast<const char*>(wire.data() + 5), length)};
            break;
        }
        case ipv6_type:
        {
            if (wire.size() != 22)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                return false;
            }
            ipv6_address address;
            std::copy_n(wire.begin() + 4, address.bytes.size(), address.bytes.begin());
            request.destination = address;
            break;
        }
        default:
            ec = boost::system::errc::make_error_code(boost::system::errc::address_family_not_supported);
            return false;
    }

    request.port = read_port(wire);
    if (request.port == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return false;
    }
    output = std::move(request);
    return true;
}

std::array<std::uint8_t, 10> encode_reply(reply value) noexcept
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

asio::awaitable<void> async_send_reply(asio::ip::tcp::socket& socket, reply value, boost::system::error_code& ec)
{
    const auto wire = encode_reply(value);
    co_await write_all(socket, wire, ec);
}

asio::awaitable<std::optional<connect_request>> async_negotiate_connect(asio::ip::tcp::socket& socket,
                                                                        const std::optional<credentials>& authentication,
                                                                        boost::system::error_code& ec)
{
    ec.clear();
    std::array<std::uint8_t, 2> greeting{};
    co_await read_exact(socket, greeting, ec);
    if (ec)
    {
        co_return std::nullopt;
    }
    if (greeting[0] != version)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::protocol_error);
        co_return std::nullopt;
    }

    std::vector<std::uint8_t> methods(greeting[1]);
    co_await read_exact(socket, methods, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    const auto selected_method = authentication ? username_password_authentication : no_authentication;
    const bool supports_selected_method = std::find(methods.begin(), methods.end(), selected_method) != methods.end();
    const std::array<std::uint8_t, 2> selection{
        version,
        supports_selected_method ? selected_method : no_acceptable_method,
    };
    co_await write_all(socket, selection, ec);
    if (ec)
    {
        co_return std::nullopt;
    }
    if (!supports_selected_method)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
        co_return std::nullopt;
    }
    if (authentication)
    {
        co_await authenticate_username_password(socket, *authentication, ec);
        if (ec)
        {
            co_return std::nullopt;
        }
    }

    std::array<std::uint8_t, 4> header{};
    co_await read_exact(socket, header, ec);
    if (ec)
    {
        co_return std::nullopt;
    }
    if (header[0] != version || header[2] != 0)
    {
        boost::system::error_code reply_ec;
        co_await async_send_reply(socket, reply::general_failure, reply_ec);
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return std::nullopt;
    }
    if (header[1] != connect_command)
    {
        boost::system::error_code reply_ec;
        co_await async_send_reply(socket, reply::command_not_supported, reply_ec);
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
        co_return std::nullopt;
    }

    std::vector<std::uint8_t> wire(header.begin(), header.end());
    switch (header[3])
    {
        case ipv4_type:
        {
            const auto previous = wire.size();
            wire.resize(previous + 6);
            co_await read_exact(socket, std::span(wire).subspan(previous), ec);
            break;
        }
        case domain_type:
        {
            std::array<std::uint8_t, 1> length{};
            co_await read_exact(socket, length, ec);
            if (ec)
            {
                co_return std::nullopt;
            }
            if (length[0] == 0)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return std::nullopt;
            }
            wire.push_back(length[0]);
            const auto previous = wire.size();
            wire.resize(previous + static_cast<std::size_t>(length[0]) + 2);
            co_await read_exact(socket, std::span(wire).subspan(previous), ec);
            break;
        }
        case ipv6_type:
        {
            const auto previous = wire.size();
            wire.resize(previous + 18);
            co_await read_exact(socket, std::span(wire).subspan(previous), ec);
            break;
        }
        default:
        {
            boost::system::error_code reply_ec;
            co_await async_send_reply(socket, reply::address_type_not_supported, reply_ec);
            ec = boost::system::errc::make_error_code(boost::system::errc::address_family_not_supported);
            co_return std::nullopt;
        }
    }
    if (ec)
    {
        co_return std::nullopt;
    }

    connect_request request;
    if (!decode_connect_request(wire, request, ec))
    {
        boost::system::error_code reply_ec;
        co_await async_send_reply(socket, reply::general_failure, reply_ec);
        co_return std::nullopt;
    }
    co_return request;
}

}    // namespace rv::socks5

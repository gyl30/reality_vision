#include "transparent.hpp"

#include <boost/asio/ip/address_v4.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>

#ifdef __linux__
#include <linux/in.h>
#include <linux/netfilter_ipv4.h>
#include <netinet/in.h>
#include <sys/socket.h>
#endif

namespace rv::transparent
{
namespace
{

[[nodiscard]] boost::system::error_code system_error() noexcept { return {errno, boost::system::generic_category()}; }

#ifdef __linux__

template <typename Socket>
boost::system::error_code set_ipv4_option(Socket& socket, const int option) noexcept
{
    const int enabled = 1;
    if (::setsockopt(socket.native_handle(), SOL_IP, option, &enabled, sizeof(enabled)) != 0)
    {
        return system_error();
    }
    return {};
}

boost::asio::ip::udp::endpoint to_udp_endpoint(const sockaddr_in& address)
{
    boost::asio::ip::address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), &address.sin_addr, bytes.size());
    return {boost::asio::ip::address_v4(bytes), ntohs(address.sin_port)};
}

#endif

}    // namespace

boost::system::error_code enable_ipv4_transparent(boost::asio::ip::tcp::acceptor& acceptor) noexcept
{
#ifdef __linux__
    return set_ipv4_option(acceptor, IP_TRANSPARENT);
#else
    static_cast<void>(acceptor);
    return boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
#endif
}

boost::system::error_code enable_ipv4_transparent(boost::asio::ip::udp::socket& socket) noexcept
{
#ifdef __linux__
    return set_ipv4_option(socket, IP_TRANSPARENT);
#else
    static_cast<void>(socket);
    return boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
#endif
}

boost::system::error_code enable_ipv4_original_destination(boost::asio::ip::udp::socket& socket) noexcept
{
#ifdef __linux__
    return set_ipv4_option(socket, IP_RECVORIGDSTADDR);
#else
    static_cast<void>(socket);
    return boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
#endif
}

boost::system::error_code get_redirect_original_destination(boost::asio::ip::tcp::socket& socket,
                                                            boost::asio::ip::tcp::endpoint& destination) noexcept
{
#ifdef __linux__
    sockaddr_in original{};
    socklen_t original_size = sizeof(original);
    if (::getsockopt(socket.native_handle(), SOL_IP, SO_ORIGINAL_DST, &original, &original_size) != 0)
    {
        return system_error();
    }
    if (original.sin_family != AF_INET)
    {
        return boost::system::errc::make_error_code(boost::system::errc::address_family_not_supported);
    }

    boost::asio::ip::address_v4::bytes_type bytes{};
    std::memcpy(bytes.data(), &original.sin_addr, bytes.size());
    destination = boost::asio::ip::tcp::endpoint(boost::asio::ip::address_v4(bytes), ntohs(original.sin_port));
    return {};
#else
    static_cast<void>(socket);
    static_cast<void>(destination);
    return boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
#endif
}

std::optional<std::size_t> receive_ipv4_original_datagram(boost::asio::ip::udp::socket& socket,
                                                          std::span<std::uint8_t> output,
                                                          boost::asio::ip::udp::endpoint& source,
                                                          boost::asio::ip::udp::endpoint& destination,
                                                          boost::system::error_code& ec) noexcept
{
#ifdef __linux__
    sockaddr_in source_address{};
    iovec iov{
        .iov_base = output.data(),
        .iov_len = output.size(),
    };
    alignas(cmsghdr) std::array<char, CMSG_SPACE(sizeof(sockaddr_in))> control{};
    msghdr message{};
    message.msg_name = &source_address;
    message.msg_namelen = sizeof(source_address);
    message.msg_iov = &iov;
    message.msg_iovlen = 1;
    message.msg_control = control.data();
    message.msg_controllen = control.size();

    const auto received = ::recvmsg(socket.native_handle(), &message, MSG_DONTWAIT);
    if (received < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            ec.clear();
            return std::nullopt;
        }
        ec = system_error();
        return std::nullopt;
    }
    if ((message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) != 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return std::nullopt;
    }
    if (source_address.sin_family != AF_INET)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::address_family_not_supported);
        return std::nullopt;
    }

    sockaddr_in original_destination{};
    bool original_destination_found = false;
    for (auto* header = CMSG_FIRSTHDR(&message); header != nullptr; header = CMSG_NXTHDR(&message, header))
    {
        if (header->cmsg_level == SOL_IP && header->cmsg_type == IP_ORIGDSTADDR && header->cmsg_len >= CMSG_LEN(sizeof(sockaddr_in)))
        {
            std::memcpy(&original_destination, CMSG_DATA(header), sizeof(original_destination));
            original_destination_found = true;
            break;
        }
    }
    if (!original_destination_found || original_destination.sin_family != AF_INET)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::no_message_available);
        return std::nullopt;
    }

    source = to_udp_endpoint(source_address);
    destination = to_udp_endpoint(original_destination);
    ec.clear();
    return static_cast<std::size_t>(received);
#else
    static_cast<void>(socket);
    static_cast<void>(output);
    static_cast<void>(source);
    static_cast<void>(destination);
    ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
    return std::nullopt;
#endif
}

}    // namespace rv::transparent

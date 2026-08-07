#include "transparent.hpp"

#include <boost/asio/ip/address_v4.hpp>
#include <boost/system/errc.hpp>

#include <array>
#include <cerrno>
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

[[nodiscard]] boost::system::error_code system_error() noexcept
{
    return {errno, boost::system::generic_category()};
}

}    // namespace

boost::system::error_code enable_ipv4_transparent(boost::asio::ip::tcp::acceptor& acceptor) noexcept
{
#ifdef __linux__
    const int enabled = 1;
    if (::setsockopt(acceptor.native_handle(), SOL_IP, IP_TRANSPARENT, &enabled, sizeof(enabled)) != 0)
    {
        return system_error();
    }
    return {};
#else
    static_cast<void>(acceptor);
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

}    // namespace rv::transparent

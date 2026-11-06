#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <boost/system/errc.hpp>

#include "tun_device.hpp"

namespace rv::tun
{
namespace
{

boost::system::error_code errno_error() { return {errno, boost::system::system_category()}; }

bool set_interface_mtu(const char* name, const std::uint16_t mtu, boost::system::error_code& ec)
{
    const int control = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (control < 0)
    {
        ec = errno_error();
        return false;
    }
    ifreq request{};
    std::strncpy(request.ifr_name, name, IFNAMSIZ - 1);
    request.ifr_mtu = mtu;
    const bool ok = ::ioctl(control, SIOCSIFMTU, &request) == 0;
    if (!ok)
    {
        ec = errno_error();
    }
    ::close(control);
    return ok;
}

}    // namespace

tun_device::~tun_device() { close(); }

bool tun_device::open(const std::string& requested_name, const std::uint16_t mtu, boost::system::error_code& ec)
{
    close();
    if (requested_name.size() >= IFNAMSIZ)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::filename_too_long);
        return false;
    }

    const int fd = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd < 0)
    {
        ec = errno_error();
        return false;
    }

    ifreq request{};
    request.ifr_flags = static_cast<short>(IFF_TUN | IFF_NO_PI);
    if (!requested_name.empty())
    {
        std::memcpy(request.ifr_name, requested_name.c_str(), requested_name.size() + 1);
    }

    if (::ioctl(fd, TUNSETIFF, &request) != 0)
    {
        ec = errno_error();
        ::close(fd);
        return false;
    }

    if (!set_interface_mtu(request.ifr_name, mtu, ec))
    {
        ::close(fd);
        return false;
    }

    fd_ = fd;
    name_ = request.ifr_name;
    ec.clear();
    return true;
}

void tun_device::close() noexcept
{
    if (fd_ >= 0)
    {
        ::close(fd_);
        fd_ = -1;
    }
    name_.clear();
}

std::ptrdiff_t tun_device::read_packet(std::uint8_t* data,
                                       const std::size_t capacity,
                                       boost::system::error_code& ec) const
{
    const auto result = ::read(fd_, data, capacity);
    if (result < 0)
    {
        ec = errno_error();
        return -1;
    }
    ec.clear();
    return result;
}

std::ptrdiff_t tun_device::write_packet(const std::uint8_t* data,
                                        const std::size_t size,
                                        boost::system::error_code& ec) const
{
    const auto result = ::write(fd_, data, size);
    if (result < 0)
    {
        ec = errno_error();
        return -1;
    }
    ec.clear();
    return result;
}

}    // namespace rv::tun

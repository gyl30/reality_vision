#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>

#include <linux/if_tun.h>
#include <net/if.h>
#include <sys/ioctl.h>

#include <boost/system/errc.hpp>

#include "tun_device.hpp"

namespace rv::tun
{
namespace
{

boost::system::error_code errno_error() { return {errno, boost::system::system_category()}; }

}    // namespace

tun_device::~tun_device() { close(); }

bool tun_device::open(const std::string& requested_name, boost::system::error_code& ec)
{
    close();

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
        std::strncpy(request.ifr_name, requested_name.c_str(), IFNAMSIZ - 1);
    }

    if (::ioctl(fd, TUNSETIFF, &request) != 0)
    {
        ec = errno_error();
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

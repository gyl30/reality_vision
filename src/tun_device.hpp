#ifndef REALITY_VISION_TUN_DEVICE_HPP
#define REALITY_VISION_TUN_DEVICE_HPP

#include <cstddef>
#include <cstdint>
#include <string>

#include <boost/system/error_code.hpp>

namespace rv::tun
{

class tun_device
{
   public:
    tun_device() = default;
    ~tun_device();

    tun_device(const tun_device&) = delete;
    tun_device& operator=(const tun_device&) = delete;

    [[nodiscard]] bool open(const std::string& requested_name, boost::system::error_code& ec);
    void close() noexcept;

    [[nodiscard]] std::ptrdiff_t read_packet(std::uint8_t* data,
                                             std::size_t capacity,
                                             boost::system::error_code& ec) const;
    [[nodiscard]] std::ptrdiff_t write_packet(const std::uint8_t* data,
                                              std::size_t size,
                                              boost::system::error_code& ec) const;

    [[nodiscard]] int native_handle() const noexcept { return fd_; }
    [[nodiscard]] const std::string& name() const noexcept { return name_; }

   private:
    int fd_ = -1;
    std::string name_;
};

}    // namespace rv::tun

#endif    // REALITY_VISION_TUN_DEVICE_HPP

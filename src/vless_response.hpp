#ifndef REALITY_VISION_VLESS_RESPONSE_HPP
#define REALITY_VISION_VLESS_RESPONSE_HPP

#include "reality_stream.hpp"
#include "stream_io.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/system/errc.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>

namespace rv::vless
{

[[nodiscard]] inline boost::asio::awaitable<void> read_response_header(reality::reality_stream& reality, boost::system::error_code& ec)
{
    constexpr std::uint8_t kVersion = 0;
    constexpr std::size_t kMaximumAddonLength = std::numeric_limits<std::uint8_t>::max();

    std::array<std::uint8_t, 2> header{};
    co_await net::read_exact(reality, header, ec);
    if (ec)
    {
        co_return;
    }
    if (header[0] != kVersion)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        co_return;
    }

    if (header[1] == 0)
    {
        co_return;
    }

    std::array<std::uint8_t, kMaximumAddonLength> addon{};
    co_await net::read_exact(reality, std::span(addon).first(header[1]), ec);
}

}    // namespace rv::vless

#endif    // REALITY_VISION_VLESS_RESPONSE_HPP

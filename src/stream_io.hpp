#ifndef REALITY_VISION_STREAM_IO_HPP
#define REALITY_VISION_STREAM_IO_HPP

#include <boost/asio/awaitable.hpp>
#include <boost/asio/error.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <span>

namespace rv::net
{

template <typename Stream>
[[nodiscard]] boost::asio::awaitable<void> read_exact(Stream& stream, std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    std::size_t offset = 0;
    while (offset != output.size())
    {
        const auto count = co_await stream.read(output.subspan(offset), ec);
        if (ec)
        {
            co_return;
        }
        if (count == 0)
        {
            ec = boost::asio::error::eof;
            co_return;
        }
        offset += count;
    }
}

}    // namespace rv::net

#endif    // REALITY_VISION_STREAM_IO_HPP

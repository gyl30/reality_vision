#include "vless_udp_stream.hpp"

#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <utility>
#include <vector>

namespace rv::vless
{

boost::asio::awaitable<std::optional<vless_udp_stream>> vless_udp_stream::connect(reality::reality_stream reality,
                                                                                  client_config configuration,
                                                                                  std::string session_id,
                                                                                  boost::system::error_code& ec)
{
    const auto request = encode_udp_request(configuration, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_await reality.write(request, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    spdlog::info("{} vless udp request header sent", session_id);
    co_return vless_udp_stream(std::move(reality), std::move(session_id));
}

vless_udp_stream::vless_udp_stream(reality::reality_stream reality, std::string session_id)
    : reality_(std::move(reality)), session_id_(std::move(session_id))
{
}

boost::asio::awaitable<void> vless_udp_stream::read_exact(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    std::size_t offset = 0;
    while (offset != output.size())
    {
        const auto count = co_await reality_.read(output.subspan(offset), ec);
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

boost::asio::awaitable<void> vless_udp_stream::read_response_header(boost::system::error_code& ec)
{
    std::array<std::uint8_t, 2> header{};
    co_await read_exact(header, ec);
    if (ec)
    {
        co_return;
    }
    if (header[0] != 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        co_return;
    }

    if (header[1] != 0)
    {
        std::vector<std::uint8_t> addon(header[1]);
        co_await read_exact(addon, ec);
        if (ec)
        {
            co_return;
        }
    }

    response_header_pending_ = false;
    spdlog::info("{} vless udp response header accepted", session_id_);
}

boost::asio::awaitable<void> vless_udp_stream::write_datagram(std::span<const std::uint8_t> payload, boost::system::error_code& ec)
{
    if (payload.empty())
    {
        co_return;
    }
    if (payload.size() > std::numeric_limits<std::uint16_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return;
    }

    std::vector<std::uint8_t> wire;
    wire.reserve(payload.size() + 2);
    wire.push_back(static_cast<std::uint8_t>(payload.size() >> 8U));
    wire.push_back(static_cast<std::uint8_t>(payload.size()));
    wire.insert(wire.end(), payload.begin(), payload.end());
    co_await reality_.write(wire, ec);
}

boost::asio::awaitable<std::vector<std::uint8_t>> vless_udp_stream::read_datagram(boost::system::error_code& ec)
{
    if (response_header_pending_)
    {
        co_await read_response_header(ec);
        if (ec)
        {
            co_return std::vector<std::uint8_t>{};
        }
    }

    std::array<std::uint8_t, 2> length_bytes{};
    co_await read_exact(length_bytes, ec);
    if (ec)
    {
        co_return std::vector<std::uint8_t>{};
    }

    const auto length = static_cast<std::size_t>(length_bytes[0]) << 8U | static_cast<std::size_t>(length_bytes[1]);
    if (length == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return std::vector<std::uint8_t>{};
    }

    std::vector<std::uint8_t> payload(length);
    co_await read_exact(payload, ec);
    if (ec)
    {
        co_return std::vector<std::uint8_t>{};
    }
    co_return payload;
}

void vless_udp_stream::shutdown() noexcept { reality_.shutdown(); }

}    // namespace rv::vless

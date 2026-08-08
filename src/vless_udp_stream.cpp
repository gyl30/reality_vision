#include "vless_udp_stream.hpp"

#include "byte_order.hpp"
#include "byte_writer.hpp"
#include "vless_response.hpp"

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
namespace
{

constexpr std::size_t kDatagramLengthSize = 2;

}    // namespace

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

boost::asio::awaitable<void> vless_udp_stream::write_datagram(std::span<const std::uint8_t> payload, boost::system::error_code& ec)
{
    ec.clear();
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
    wire.reserve(payload.size() + kDatagramLengthSize);
    core::append_be16(wire, static_cast<std::uint16_t>(payload.size()));
    wire.insert(wire.end(), payload.begin(), payload.end());
    co_await reality_.write(wire, ec);
}

boost::asio::awaitable<std::vector<std::uint8_t>> vless_udp_stream::read_datagram(boost::system::error_code& ec)
{
    ec.clear();
    if (response_header_pending_)
    {
        co_await vless::read_response_header(reality_, ec);
        if (ec)
        {
            co_return std::vector<std::uint8_t>{};
        }
        response_header_pending_ = false;
        spdlog::info("{} vless udp response header accepted", session_id_);
    }

    std::array<std::uint8_t, kDatagramLengthSize> length_bytes{};
    co_await net::read_exact(reality_, length_bytes, ec);
    if (ec)
    {
        co_return std::vector<std::uint8_t>{};
    }

    const auto length = static_cast<std::size_t>(core::read_be16(length_bytes.data()));
    if (length == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return std::vector<std::uint8_t>{};
    }

    std::vector<std::uint8_t> payload(length);
    co_await net::read_exact(reality_, payload, ec);
    if (ec)
    {
        co_return std::vector<std::uint8_t>{};
    }
    co_return payload;
}

void vless_udp_stream::shutdown() noexcept { reality_.shutdown(); }

}    // namespace rv::vless

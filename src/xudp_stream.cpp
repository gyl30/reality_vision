#include <array>
#include <utility>
#include <algorithm>

#include <spdlog/spdlog.h>
#include <boost/asio/error.hpp>

#include "crypto.hpp"
#include "stream_io.hpp"
#include "byte_order.hpp"
#include "xudp_stream.hpp"

namespace rv::xudp
{
namespace
{

constexpr std::size_t kGlobalIdKeySize = 32;

}    // namespace

global_id make_global_id(const std::string_view client_source)
{
    // 进程级随机密钥，避免从 ID 推回客户端地址；取不到随机数时返回空 ID，服务端按非 cone 会话处理。
    static const auto key = []
    {
        std::array<std::uint8_t, kGlobalIdKeySize> output{};
        boost::system::error_code ec;
        crypto::random_bytes(output, ec);
        return std::pair{output, !ec};
    }();

    global_id output{};
    if (!key.second)
    {
        return output;
    }
    boost::system::error_code ec;
    const auto mac = crypto::hmac(crypto::hash_algorithm::kSha256,
                                  key.first,
                                  std::span(reinterpret_cast<const std::uint8_t*>(client_source.data()), client_source.size()),
                                  ec);
    if (!ec && mac.size() >= output.size())
    {
        std::copy_n(mac.begin(), output.size(), output.begin());
    }
    return output;
}

xudp_stream::xudp_stream(vision::vision_stream vision, const global_id id, std::string session_id)
    : vision_(std::move(vision)), id_(id), session_id_(std::move(session_id))
{
}

boost::asio::awaitable<void> xudp_stream::write_datagram(const endpoint& destination,
                                                         const std::span<const std::uint8_t> payload,
                                                         boost::system::error_code& ec)
{
    // 首个数据报以 New 帧打开会话，此后每个数据报都用 Keep 帧携带各自的目的地址。
    const auto frame = first_destination_ ? encode_keep_frame(destination, payload, ec) : encode_new_frame(destination, id_, payload, ec);
    if (ec)
    {
        co_return;
    }
    if (!first_destination_)
    {
        first_destination_ = destination;
        spdlog::info("{} xudp session opened to {}", session_id_, net::format_address_port(destination.address, destination.port));
    }
    co_await vision_.write(frame, ec);
}

boost::asio::awaitable<datagram> xudp_stream::read_datagram(boost::system::error_code& ec)
{
    for (;;)
    {
        std::array<std::uint8_t, kFrameLengthSize> length{};
        co_await net::read_exact(vision_, length, ec);
        if (ec)
        {
            co_return datagram{};
        }
        std::vector<std::uint8_t> metadata(core::read_be16(length.data()));
        co_await net::read_exact(vision_, metadata, ec);
        if (ec)
        {
            co_return datagram{};
        }

        const auto parsed = parse_frame_metadata(metadata, ec);
        if (ec)
        {
            co_return datagram{};
        }
        if (parsed.kind == frame_kind::kEnd)
        {
            ec = boost::asio::error::eof;
            co_return datagram{};
        }
        if (!parsed.has_data)
        {
            continue;
        }

        co_await net::read_exact(vision_, length, ec);
        if (ec)
        {
            co_return datagram{};
        }
        std::vector<std::uint8_t> payload(core::read_be16(length.data()));
        co_await net::read_exact(vision_, payload, ec);
        if (ec)
        {
            co_return datagram{};
        }
        if (parsed.kind == frame_kind::kDiscard || payload.empty())
        {
            continue;
        }

        // Xray 在回包未携带地址时由入站使用原始目标，这里同样回退到首个目的地址。
        auto source = parsed.source ? *parsed.source : first_destination_.value_or(endpoint{});
        co_return datagram{.source = std::move(source), .payload = std::move(payload)};
    }
}

void xudp_stream::shutdown() noexcept { vision_.shutdown(); }

}    // namespace rv::xudp

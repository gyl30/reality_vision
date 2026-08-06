#include "vless_stream.hpp"

#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>
#include <spdlog/spdlog.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace rv::vless
{
namespace
{

boost::asio::awaitable<void> read_exact(reality::reality_stream& stream, std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    std::size_t offset = 0;
    while (offset != output.size())
    {
        const auto count = co_await stream.async_read_some(output.subspan(offset), ec);
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

}    // namespace

boost::asio::awaitable<std::optional<vless_stream>> vless_stream::connect(reality::reality_stream lower,
                                                                          client_config config,
                                                                          std::string id,
                                                                          boost::system::error_code& ec)
{
    const auto request = encode_tcp_request(config, ec);
    if (ec)
    {
        co_return std::nullopt;
    }
    co_await lower.async_write_all(request, ec);
    if (ec)
    {
        co_return std::nullopt;
    }
    spdlog::info("{} vless tcp request header sent", id);
    co_return vless_stream(std::move(lower), std::move(id));
}

vless_stream::vless_stream(reality::reality_stream lower, std::string log) : lower_(std::move(lower)), id_(std::move(log)) {}

boost::asio::awaitable<void> vless_stream::read_response_header(boost::system::error_code& ec)
{
    std::array<std::uint8_t, 2> header{};
    co_await read_exact(lower_, header, ec);
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
        co_await read_exact(lower_, addon, ec);
        if (ec)
        {
            co_return;
        }
    }
    response_pending_ = false;
    spdlog::info("{} vless response header accepted", id_);
}

boost::asio::awaitable<std::size_t> vless_stream::async_read_some(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (response_pending_)
    {
        co_await read_response_header(ec);
        if (ec)
        {
            co_return 0;
        }
    }
    co_return co_await lower_.async_read_some(output, ec);
}

boost::asio::awaitable<void> vless_stream::async_write_all(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    co_await lower_.async_write_all(input, ec);
}

boost::asio::awaitable<void> vless_stream::async_shutdown_send(boost::system::error_code& ec) { co_await lower_.async_shutdown_send(ec); }

bool vless_stream::switch_receive_to_raw(boost::system::error_code& ec)
{
    if (response_pending_)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_permitted);
        return false;
    }
    return lower_.switch_receive_to_raw(ec);
}

boost::asio::awaitable<void> vless_stream::async_write_final_tls_and_switch(std::span<const std::uint8_t> final_plaintext,
                                                                            boost::system::error_code& ec)
{
    co_await lower_.async_write_final_tls_and_switch(final_plaintext, ec);
}

void vless_stream::shutdown() noexcept { lower_.shutdown(); }

}    // namespace rv::vless

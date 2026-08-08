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

}    // namespace

boost::asio::awaitable<std::optional<vless_stream>> vless_stream::connect(reality::reality_stream reality,
                                                                          client_config configuration,
                                                                          std::string session_id,
                                                                          boost::system::error_code& ec)
{
    const auto request = encode_tcp_request(configuration, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_await reality.write(request, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    spdlog::info("{} vless tcp request header sent", session_id);
    co_return vless_stream(std::move(reality), std::move(session_id));
}

vless_stream::vless_stream(reality::reality_stream reality, std::string session_id) : reality_(std::move(reality)), session_id_(std::move(session_id))
{
}

boost::asio::awaitable<void> vless_stream::read_response_header(boost::system::error_code& ec)
{
    std::array<std::uint8_t, 2> header{};
    co_await read_exact(reality_, header, ec);
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
        co_await read_exact(reality_, addon, ec);
        if (ec)
        {
            co_return;
        }
    }

    response_header_pending_ = false;
    spdlog::info("{} vless response header accepted", session_id_);
}

boost::asio::awaitable<std::size_t> vless_stream::read(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (output.empty())
    {
        co_return 0;
    }

    if (response_header_pending_)
    {
        co_await read_response_header(ec);
        if (ec)
        {
            co_return 0;
        }
    }

    co_return co_await reality_.read(output, ec);
}

boost::asio::awaitable<void> vless_stream::write(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    co_await reality_.write(input, ec);
}

boost::asio::awaitable<void> vless_stream::shutdown_send(boost::system::error_code& ec) { co_await reality_.shutdown_send(ec); }

void vless_stream::switch_receive_to_raw(boost::system::error_code& ec)
{
    if (response_header_pending_)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_permitted);
        return;
    }
    reality_.switch_receive_to_raw(ec);
}

boost::asio::awaitable<void> vless_stream::write_final_tls_and_switch_to_raw(std::span<const std::uint8_t> final_plaintext,
                                                                             boost::system::error_code& ec)
{
    co_await reality_.write_final_tls_and_switch_to_raw(final_plaintext, ec);
}

void vless_stream::shutdown() noexcept { reality_.shutdown(); }

}    // namespace rv::vless

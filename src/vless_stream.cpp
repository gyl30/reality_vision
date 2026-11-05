#include <span>
#include <cstddef>
#include <cstdint>
#include <utility>

#include <spdlog/spdlog.h>

#include "vless_stream.hpp"
#include "vless_response.hpp"

namespace rv::vless
{

vless_stream vless_stream::connect(reality::reality_stream reality, std::vector<std::uint8_t> request, std::string session_id)
{
    return vless_stream(std::move(reality), std::move(request), std::move(session_id));
}

vless_stream::vless_stream(reality::reality_stream reality, std::vector<std::uint8_t> pending_request, std::string session_id)
    : reality_(std::move(reality)), pending_request_(std::move(pending_request)), session_id_(std::move(session_id))
{
}

std::span<const std::uint8_t> vless_stream::take_request_with(const std::span<const std::uint8_t> input)
{
    if (pending_request_.empty())
    {
        return input;
    }
    pending_request_.insert(pending_request_.end(), input.begin(), input.end());
    return pending_request_;
}

void vless_stream::log_request_sent() const
{
    spdlog::info("{} vless request header sent", session_id_);
}

boost::asio::awaitable<std::size_t> vless_stream::read(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (output.empty())
    {
        co_return 0;
    }

    if (response_header_pending_)
    {
        co_await vless::read_response_header(reality_, ec);
        if (ec)
        {
            co_return 0;
        }
        response_header_pending_ = false;
        spdlog::info("{} vless response header accepted", session_id_);
    }

    co_return co_await reality_.read(output, ec);
}

boost::asio::awaitable<void> vless_stream::write(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    const bool request_pending = !pending_request_.empty();
    co_await reality_.write(take_request_with(input), ec);
    pending_request_.clear();
    if (!ec && request_pending)
    {
        log_request_sent();
    }
}

boost::asio::awaitable<void> vless_stream::shutdown_send(boost::system::error_code& ec)
{
    if (!pending_request_.empty())
    {
        co_await write({}, ec);
        if (ec)
        {
            co_return;
        }
    }
    co_await reality_.shutdown_send(ec);
}

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
    const bool request_pending = !pending_request_.empty();
    co_await reality_.write_final_tls_and_switch_to_raw(take_request_with(final_plaintext), ec);
    pending_request_.clear();
    if (!ec && request_pending)
    {
        log_request_sent();
    }
}

void vless_stream::shutdown() noexcept { reality_.shutdown(); }

}    // namespace rv::vless

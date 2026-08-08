#include "vision_stream.hpp"

#include "stream_io.hpp"

#include <boost/asio/error.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>

namespace rv::vision
{

boost::asio::awaitable<std::optional<vision_stream>> vision_stream::connect(vless::vless_stream vless,
                                                                            std::array<std::uint8_t, kUserIdSize> user_id,
                                                                            std::string session_id,
                                                                            boost::system::error_code& ec)
{
    vision_stream stream(std::move(vless), user_id, std::move(session_id));
    const auto initial_frame = encode_frame(command::kContinuePadding, std::span<const std::uint8_t, kUserIdSize>(stream.user_id_), {}, true, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_await stream.vless_.write(initial_frame, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    spdlog::info("{} initial empty vision padding frame sent", stream.session_id_);
    co_return std::move(stream);
}

vision_stream::vision_stream(vless::vless_stream vless, std::array<std::uint8_t, kUserIdSize> user_id, std::string session_id)
    : vless_(std::move(vless)), user_id_(user_id), session_id_(std::move(session_id))
{
}

boost::asio::awaitable<bool> vision_stream::read_next_frame_header(boost::system::error_code& ec)
{
    std::array<std::uint8_t, kFullHeaderSize> storage{};
    const auto header_size = expect_user_id_ ? kFullHeaderSize : kShortHeaderSize;

    const auto first_byte_count = co_await vless_.read(std::span(storage).first(1), ec);
    if (ec)
    {
        co_return false;
    }
    if (first_byte_count == 0)
    {
        co_return false;
    }

    co_await net::read_exact(vless_, std::span(storage.data() + 1, header_size - 1), ec);
    if (ec)
    {
        co_return false;
    }

    frame_header header;
    ec = decode_header(std::span<const std::uint8_t>(storage.data(), header_size), expect_user_id_, user_id_, header);
    if (ec)
    {
        co_return false;
    }

    expect_user_id_ = false;
    received_command_ = header.frame_command;
    content_remaining_ = header.content_length;
    padding_remaining_ = header.padding_length;
    receive_phase_ = receive_phase::kContent;

    spdlog::info("{} vision frame command {} content {} padding {}",
                 session_id_,
                 static_cast<unsigned int>(header.frame_command),
                 header.content_length,
                 header.padding_length);
    co_return true;
}

boost::asio::awaitable<std::size_t> vision_stream::read_frame_content(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (content_remaining_ == 0)
    {
        receive_phase_ = receive_phase::kPadding;
        co_return 0;
    }

    const auto requested = std::min(output.size(), content_remaining_);
    const auto count = co_await vless_.read(output.first(requested), ec);
    if (ec)
    {
        co_return 0;
    }
    if (count == 0)
    {
        ec = boost::asio::error::eof;
        co_return 0;
    }

    content_remaining_ -= count;
    server_hello_tracker_.observe(output.first(count));
    if (!direct_mode_allowed_ && server_hello_tracker_.direct_supported())
    {
        direct_mode_allowed_ = true;
        spdlog::info("{} inner tls 1.3 server hello permits vision direct mode", session_id_);
    }

    co_return count;
}

boost::asio::awaitable<void> vision_stream::discard_frame_padding(boost::system::error_code& ec)
{
    constexpr std::size_t kPaddingDiscardBufferSize = 1024;
    std::array<std::uint8_t, kPaddingDiscardBufferSize> discard_buffer{};
    while (padding_remaining_ != 0)
    {
        const auto requested = std::min(padding_remaining_, discard_buffer.size());
        const auto count = co_await vless_.read(std::span(discard_buffer.data(), requested), ec);
        if (ec)
        {
            co_return;
        }
        if (count == 0)
        {
            ec = boost::asio::error::eof;
            co_return;
        }
        padding_remaining_ -= count;
    }
}

boost::asio::awaitable<void> vision_stream::finish_received_frame(boost::system::error_code& ec)
{
    co_await discard_frame_padding(ec);
    if (ec)
    {
        co_return;
    }

    switch (received_command_)
    {
        case command::kContinuePadding:
            receive_phase_ = receive_phase::kHeader;
            break;
        case command::kEndPadding:
            receive_phase_ = receive_phase::kPassthrough;
            break;
        case command::kDirect:
            vless_.switch_receive_to_raw(ec);
            if (ec)
            {
                co_return;
            }
            receive_phase_ = receive_phase::kPassthrough;
            spdlog::info("{} vision receive direction entered direct mode", session_id_);
            break;
    }
}

boost::asio::awaitable<std::size_t> vision_stream::read(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (output.empty())
    {
        co_return 0;
    }

    for (;;)
    {
        switch (receive_phase_)
        {
            case receive_phase::kPassthrough:
                co_return co_await vless_.read(output, ec);

            case receive_phase::kHeader:
                if (!co_await read_next_frame_header(ec))
                {
                    co_return 0;
                }
                break;

            case receive_phase::kContent:
            {
                const auto count = co_await read_frame_content(output, ec);
                if (ec)
                {
                    co_return count;
                }
                if (count != 0)
                {
                    co_return count;
                }
                break;
            }

            case receive_phase::kPadding:
                co_await finish_received_frame(ec);
                if (ec)
                {
                    co_return 0;
                }
                break;
        }
    }
}

vision_stream::send_plan vision_stream::make_send_plan(const std::span<const std::uint8_t> input) noexcept
{
    const auto observation = client_tls_record_tracker_.observe(input);

    send_plan plan{
        .final_command = command::kContinuePadding,
        .vision_framed_size = input.size(),
        .use_long_padding = client_tls_record_tracker_.tls_detected(),
    };

    if (observation.kind == client_stream_kind::kNonTls || observation.tracking_failed)
    {
        plan.final_command = command::kEndPadding;
        return plan;
    }

    if (observation.encrypted_record_end_offset)
    {
        plan.vision_framed_size = *observation.encrypted_record_end_offset;
        plan.final_command = direct_mode_allowed_ ? command::kDirect : command::kEndPadding;
    }

    return plan;
}

boost::asio::awaitable<void> vision_stream::write_vision_frames(const std::span<const std::uint8_t> input,
                                                                const command final_command,
                                                                const bool use_long_padding,
                                                                boost::system::error_code& ec)
{
    std::size_t offset = 0;
    bool first_frame = true;
    while (first_frame || offset != input.size())
    {
        first_frame = false;
        const auto content_size = std::min(kMaximumContentSize, input.size() - offset);
        const bool is_final_frame = offset + content_size == input.size();
        const auto frame_command = is_final_frame ? final_command : command::kContinuePadding;

        const auto frame = encode_frame(frame_command, std::nullopt, input.subspan(offset, content_size), use_long_padding, ec);
        if (ec)
        {
            co_return;
        }

        if (is_final_frame && frame_command == command::kDirect)
        {
            co_await vless_.write_final_tls_and_switch_to_raw(frame, ec);
        }
        else
        {
            co_await vless_.write(frame, ec);
        }
        if (ec)
        {
            co_return;
        }

        offset += content_size;
    }
}

boost::asio::awaitable<void> vision_stream::write(const std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    if (input.empty())
    {
        co_return;
    }
    if (!send_padding_active_)
    {
        co_await vless_.write(input, ec);
        co_return;
    }

    const auto plan = make_send_plan(input);
    co_await write_vision_frames(input.first(plan.vision_framed_size), plan.final_command, plan.use_long_padding, ec);
    if (ec)
    {
        co_return;
    }
    if (plan.final_command == command::kContinuePadding)
    {
        co_return;
    }

    send_padding_active_ = false;
    spdlog::info("{} vision send padding ended with command {}", session_id_, static_cast<unsigned int>(plan.final_command));

    if (plan.vision_framed_size != input.size())
    {
        co_await vless_.write(input.subspan(plan.vision_framed_size), ec);
    }
}

boost::asio::awaitable<void> vision_stream::end_padding_before_shutdown(boost::system::error_code& ec)
{
    if (!send_padding_active_)
    {
        co_return;
    }

    const auto frame = encode_frame(command::kEndPadding, std::nullopt, {}, client_tls_record_tracker_.tls_detected(), ec);
    if (ec)
    {
        co_return;
    }

    co_await vless_.write(frame, ec);
    if (ec)
    {
        co_return;
    }

    send_padding_active_ = false;
    spdlog::info("{} vision send padding ended with command {}", session_id_, static_cast<unsigned int>(command::kEndPadding));
}

boost::asio::awaitable<void> vision_stream::shutdown_send(boost::system::error_code& ec)
{
    co_await end_padding_before_shutdown(ec);
    if (ec)
    {
        co_return;
    }
    co_await vless_.shutdown_send(ec);
}

void vision_stream::shutdown() noexcept { vless_.shutdown(); }

}    // namespace rv::vision

#include "vision_stream.hpp"

#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>
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
namespace
{

boost::asio::awaitable<void> read_exact(vless::vless_stream& stream, std::span<std::uint8_t> output, boost::system::error_code& ec)
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

boost::asio::awaitable<std::optional<vision_stream>> vision_stream::connect(vless::vless_stream lower,
                                                                            std::array<std::uint8_t, user_id_size> user_id,
                                                                            std::string log,
                                                                            boost::system::error_code& ec)
{
    vision_stream stream(std::move(lower), user_id, std::move(log));
    const auto initial_frame = encode_frame(command::continue_padding, std::span<const std::uint8_t, user_id_size>(stream.user_id_), {}, true, ec);
    if (ec)
    {
        co_return std::nullopt;
    }
    co_await stream.lower_.async_write_all(initial_frame, ec);
    if (ec)
    {
        co_return std::nullopt;
    }
    stream.write_sent_user_id_ = true;
    spdlog::info("[{}] initial empty vision padding frame sent", stream.log_);
    co_return std::move(stream);
}

vision_stream::vision_stream(vless::vless_stream lower, std::array<std::uint8_t, user_id_size> user_id, std::string log)
    : lower_(std::move(lower)), user_id_(user_id), log_(std::move(log))
{
}

boost::asio::awaitable<bool> vision_stream::read_frame_header(boost::system::error_code& ec)
{
    std::array<std::uint8_t, full_header_size> storage{};
    const auto size = read_needs_user_id_ ? full_header_size : short_header_size;
    const auto first = co_await lower_.async_read_some(std::span(storage).first(1), ec);
    if (ec)
    {
        co_return false;
    }
    if (first == 0)
    {
        co_return false;
    }
    co_await read_exact(lower_, std::span(storage.data() + 1, size - 1), ec);
    if (ec)
    {
        co_return false;
    }

    frame_header header;
    if (!decode_header(std::span<const std::uint8_t>(storage.data(), size), read_needs_user_id_, user_id_, header, ec))
    {
        co_return false;
    }
    read_needs_user_id_ = false;
    read_command_ = header.frame_command;
    remaining_content_ = header.content_length;
    remaining_padding_ = header.padding_length;
    read_phase_ = read_phase::content;
    spdlog::info("[{}] vision frame command {} content {} padding {}",
                 log_,
                 static_cast<unsigned int>(header.frame_command),
                 header.content_length,
                 header.padding_length);
    co_return true;
}

boost::asio::awaitable<void> vision_stream::discard_padding(boost::system::error_code& ec)
{
    std::array<std::uint8_t, 1024> discard{};
    while (remaining_padding_ != 0)
    {
        const auto wanted = std::min(remaining_padding_, discard.size());
        const auto count = co_await lower_.async_read_some(std::span(discard.data(), wanted), ec);
        if (ec)
        {
            co_return;
        }
        if (count == 0)
        {
            ec = boost::asio::error::eof;
            co_return;
        }
        remaining_padding_ -= count;
    }
}

boost::asio::awaitable<std::size_t> vision_stream::async_read_some(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    for (;;)
    {
        if (read_phase_ == read_phase::through)
        {
            co_return co_await lower_.async_read_some(output, ec);
        }
        if (read_phase_ == read_phase::header)
        {
            const auto available = co_await read_frame_header(ec);
            if (ec || !available)
            {
                co_return 0;
            }
            continue;
        }
        if (read_phase_ == read_phase::content)
        {
            if (remaining_content_ == 0)
            {
                read_phase_ = read_phase::padding;
                continue;
            }
            const auto wanted = std::min(output.size(), remaining_content_);
            const auto count = co_await lower_.async_read_some(output.first(wanted), ec);
            if (ec)
            {
                co_return 0;
            }
            if (count == 0)
            {
                ec = boost::asio::error::eof;
                co_return 0;
            }
            remaining_content_ -= count;
            server_hello_filter_.observe(output.first(count));
            if (!direct_enabled_ && server_hello_filter_.direct_supported())
            {
                direct_enabled_ = true;
                spdlog::info("[{}] inner tls 1.3 server hello permits vision direct mode", log_);
            }
            co_return count;
        }

        co_await discard_padding(ec);
        if (ec)
        {
            co_return 0;
        }
        switch (read_command_)
        {
            case command::continue_padding:
                read_phase_ = read_phase::header;
                break;
            case command::end_padding:
                read_phase_ = read_phase::through;
                break;
            case command::direct:
                if (!lower_.switch_receive_to_raw(ec))
                {
                    co_return 0;
                }
                read_phase_ = read_phase::through;
                spdlog::info("[{}] vision receive direction entered direct mode", log_);
                break;
        }
    }
}

boost::asio::awaitable<void> vision_stream::async_write_all(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    if (!write_padding_)
    {
        co_await lower_.async_write_all(input, ec);
        co_return;
    }

    const auto found_client_hello = contains_tls_client_hello(input);
    const auto seen_tls = write_seen_tls_ || found_client_hello;
    const auto application_boundary = seen_tls && starts_tls13_application_data(input) && consists_of_complete_tls13_application_records(input);
    const auto end_padding = application_boundary || (!seen_tls && !found_client_hello);
    command final_command = command::continue_padding;

    if (end_padding)
    {
        if (application_boundary && direct_enabled_)
        {
            final_command = command::direct;
        }
        else
        {
            final_command = command::end_padding;
        }
    }

    constexpr std::size_t maximum_content = xray_buffer_size - full_header_size;
    std::size_t offset = 0;
    bool sent_user_id = write_sent_user_id_;
    while (offset != input.size())
    {
        const auto count = std::min(maximum_content, input.size() - offset);
        const bool last = offset + count == input.size();
        const auto frame_command = last ? final_command : command::continue_padding;
        std::optional<std::span<const std::uint8_t, user_id_size>> user_id;
        if (!sent_user_id)
        {
            user_id.emplace(user_id_);
        }
        const auto frame = encode_frame(frame_command, user_id, input.subspan(offset, count), seen_tls, ec);
        if (ec)
        {
            co_return;
        }

        if (last && frame_command == command::direct)
        {
            co_await lower_.async_write_final_tls_and_switch(frame, ec);
        }
        else
        {
            co_await lower_.async_write_all(frame, ec);
        }
        if (ec)
        {
            co_return;
        }
        sent_user_id = true;
        offset += count;
    }

    write_sent_user_id_ = sent_user_id;
    write_seen_tls_ = seen_tls;
    if (end_padding)
    {
        write_padding_ = false;
        spdlog::info("[{}] vision send padding ended with command {}", log_, static_cast<unsigned int>(final_command));
    }
}

boost::asio::awaitable<void> vision_stream::async_shutdown_send(boost::system::error_code& ec)
{
    if (write_padding_)
    {
        std::optional<std::span<const std::uint8_t, user_id_size>> user_id;
        if (!write_sent_user_id_)
        {
            user_id.emplace(user_id_);
        }
        const auto frame = encode_frame(command::end_padding, user_id, {}, write_seen_tls_, ec);
        if (ec)
        {
            co_return;
        }
        co_await lower_.async_write_all(frame, ec);
        if (ec)
        {
            co_return;
        }
        write_sent_user_id_ = true;
        write_padding_ = false;
        spdlog::info("[{}] vision send padding ended with command 1", log_);
    }
    co_await lower_.async_shutdown_send(ec);
}

void vision_stream::shutdown() noexcept { lower_.shutdown(); }

}    // namespace rv::vision

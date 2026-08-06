#include "reality_stream.hpp"

#include "reality_handshake.hpp"

#include <boost/asio/error.hpp>
#include <boost/system/errc.hpp>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

namespace rv::reality
{
namespace
{

boost::asio::awaitable<void> read_exact(net::tcp_byte_stream& stream, std::span<std::uint8_t> output, boost::system::error_code& ec)
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

std::size_t handshake_message_length(std::span<const std::uint8_t> input) noexcept
{
    return 4 + (static_cast<std::size_t>(input[1]) << 16U | static_cast<std::size_t>(input[2]) << 8U | static_cast<std::size_t>(input[3]));
}

}    // namespace

boost::asio::awaitable<std::optional<reality_stream>> reality_stream::connect(net::tcp_byte_stream lower,
                                                                              client_config config,
                                                                              std::string log,
                                                                              boost::system::error_code& ec)
{
    auto result = co_await perform_client_handshake(lower, config, log, ec);
    if (ec || !result)
    {
        co_return std::nullopt;
    }
    co_return reality_stream(std::move(lower), std::move(result->read_key), std::move(result->write_key), std::move(log));
}

reality_stream::reality_stream(net::tcp_byte_stream lower, record_key read_key, record_key write_key, std::string id)
    : lower_(std::move(lower)), read_key_(std::move(read_key)), write_key_(std::move(write_key)), id_(std::move(id))
{
}

boost::asio::awaitable<std::size_t> reality_stream::async_read_some(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (output.empty())
    {
        co_return 0;
    }
    if (!plaintext_.empty())
    {
        co_return plaintext_.copy_to(output);
    }
    if (receive_mode_ == receive_mode::raw)
    {
        const auto count = co_await lower_.async_read_some(output, ec);
        if (ec == boost::asio::error::eof)
        {
            receive_mode_ = receive_mode::closed;
            ec = {};
            co_return 0;
        }
        co_return count;
    }
    if (receive_mode_ == receive_mode::closed)
    {
        co_return 0;
    }

    for (;;)
    {
        std::array<std::uint8_t, 5> header{};
        co_await read_exact(lower_, header, ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                receive_mode_ = receive_mode::closed;
            }
            co_return 0;
        }
        const auto length = static_cast<std::size_t>(header[3]) << 8U | static_cast<std::size_t>(header[4]);
        if (length > max_tls_ciphertext)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            co_return 0;
        }
        std::vector<std::uint8_t> payload(length);
        co_await read_exact(lower_, payload, ec);
        if (ec)
        {
            co_return 0;
        }

        if (header[0] == tls_record_change_cipher_spec)
        {
            if (++useless_records_ > 3)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return 0;
            }
            continue;
        }
        if (header[0] != tls_record_application_data || header[1] != 0x03 || header[2] != 0x03)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return 0;
        }

        auto opened = read_key_.open(header, payload, ec);
        if (ec)
        {
            co_return 0;
        }
        if (opened.inner_type == tls_record_application_data)
        {
            useless_records_ = 0;
            if (!plaintext_.append(opened.content, ec))
            {
                co_return 0;
            }
            if (!plaintext_.empty())
            {
                co_return plaintext_.copy_to(output);
            }
            continue;
        }
        if (opened.inner_type == tls_record_handshake)
        {
            if (!post_handshake_.append(opened.content, ec) || !process_post_handshake(ec))
            {
                co_return 0;
            }
            continue;
        }
        if (opened.inner_type == tls_record_alert)
        {
            if (opened.content.size() == 2 && opened.content[0] == 1 && opened.content[1] == 0)
            {
                receive_mode_ = receive_mode::closed;
                co_return 0;
            }
            ec = boost::system::errc::make_error_code(boost::system::errc::connection_aborted);
            co_return 0;
        }
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        co_return 0;
    }
}

boost::asio::awaitable<void> reality_stream::write_tls(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    std::size_t offset = 0;
    while (offset != input.size())
    {
        const auto count = std::min(max_tls_plaintext, input.size() - offset);
        const auto record = write_key_.seal(tls_record_application_data, input.subspan(offset, count), ec);
        if (ec)
        {
            co_return;
        }
        co_await lower_.async_write_all(record, ec);
        if (ec)
        {
            co_return;
        }
        offset += count;
    }
}

boost::asio::awaitable<void> reality_stream::async_write_all(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    if (send_mode_ == send_mode::raw)
    {
        co_await lower_.async_write_all(input, ec);
        co_return;
    }
    if (send_mode_ != send_mode::tls)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::state_not_recoverable);
        co_return;
    }
    co_await write_tls(input, ec);
}

boost::asio::awaitable<void> reality_stream::async_shutdown_send(boost::system::error_code& ec)
{
    if (send_mode_ == send_mode::closed)
    {
        co_return;
    }
    if (send_mode_ == send_mode::draining)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_in_progress);
        co_return;
    }

    if (send_mode_ == send_mode::tls)
    {
        constexpr std::array<std::uint8_t, 2> close_notify{1, 0};
        const auto record = write_key_.seal(tls_record_alert, close_notify, ec);
        if (!ec)
        {
            co_await lower_.async_write_all(record, ec);
        }
    }
    send_mode_ = send_mode::closed;
    boost::system::error_code shutdown_ec;
    lower_.shutdown_send(shutdown_ec);
    if (!ec)
    {
        ec = shutdown_ec;
    }
}

bool reality_stream::switch_receive_to_raw(boost::system::error_code& ec)
{
    if (receive_mode_ != receive_mode::tls || !plaintext_.empty() || !post_handshake_.empty() || read_in_progress_)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_permitted);
        return false;
    }
    receive_mode_ = receive_mode::raw;
    spdlog::info("{} reality receive direction switched to raw", id_);
    return true;
}

boost::asio::awaitable<void> reality_stream::async_write_final_tls_and_switch(std::span<const std::uint8_t> final_plaintext,
                                                                              boost::system::error_code& ec)
{
    if (send_mode_ != send_mode::tls)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_permitted);
        co_return;
    }

    send_mode_ = send_mode::draining;
    co_await write_tls(final_plaintext, ec);
    if (ec)
    {
        send_mode_ = send_mode::closed;
        co_return;
    }
    send_mode_ = send_mode::raw;
    spdlog::info("{} reality send direction switched to raw", id_);
}

bool reality_stream::process_post_handshake(boost::system::error_code& ec)
{
    while (post_handshake_.size() >= 4)
    {
        const auto length = handshake_message_length(post_handshake_.data());
        if (length > 1U << 20)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return false;
        }
        if (post_handshake_.size() < length)
        {
            return true;
        }
        const auto type = post_handshake_.data()[0];
        post_handshake_.consume(length);
        if (type == 4)
        {
            continue;
        }
        if (type == 24)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
            return false;
        }
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return false;
    }
    return true;
}

void reality_stream::shutdown() noexcept
{
    receive_mode_ = receive_mode::closed;
    send_mode_ = send_mode::closed;
    lower_.shutdown();
}

}    // namespace rv::reality

#include "reality_stream.hpp"

#include "byte_order.hpp"
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

std::size_t handshake_message_length(std::span<const std::uint8_t> input) noexcept
{
    return 4 + static_cast<std::size_t>(core::read_be24(input.data() + 1));
}

}    // namespace

boost::asio::awaitable<std::optional<reality_stream>> reality_stream::connect(net::tcp_byte_stream tcp,
                                                                              client_config configuration,
                                                                              std::string session_id,
                                                                              boost::system::error_code& ec)
{
    auto handshake = co_await perform_client_handshake(tcp, configuration, session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_return reality_stream(std::move(tcp), std::move(handshake->receive_key), std::move(handshake->send_key), std::move(session_id));
}

reality_stream::reality_stream(net::tcp_byte_stream tcp, record_key receive_key, record_key send_key, std::string session_id)
    : tcp_(std::move(tcp)), receive_key_(std::move(receive_key)), send_key_(std::move(send_key)), session_id_(std::move(session_id))
{
}

boost::asio::awaitable<std::size_t> reality_stream::read(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (output.empty())
    {
        co_return 0;
    }
    if (!plaintext_buffer_.empty())
    {
        co_return plaintext_buffer_.copy_to(output);
    }
    if (receive_mode_ == receive_mode::kClosed)
    {
        co_return 0;
    }
    if (receive_mode_ == receive_mode::kRaw)
    {
        co_return co_await read_raw(output, ec);
    }

    co_return co_await read_tls(output, ec);
}

boost::asio::awaitable<std::size_t> reality_stream::read_raw(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    const auto count = co_await tcp_.read(output, ec);
    if (ec == boost::asio::error::eof)
    {
        receive_mode_ = receive_mode::kClosed;
        ec.clear();
        co_return 0;
    }
    co_return count;
}

boost::asio::awaitable<std::optional<reality_stream::encrypted_record>> reality_stream::read_tls_record(boost::system::error_code& ec)
{
    encrypted_record record;
    co_await read_exact(tcp_, record.header, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    const auto payload_size = static_cast<std::size_t>(core::read_be16(record.header.data() + 3));
    if (payload_size > kMaxTlsCiphertext)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        co_return std::nullopt;
    }

    record.payload.resize(payload_size);
    co_await read_exact(tcp_, record.payload, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_return record;
}

std::optional<std::size_t> reality_stream::process_decrypted_record(const opened_record& plaintext,
                                                                    std::span<std::uint8_t> output,
                                                                    boost::system::error_code& ec)
{
    if (plaintext.inner_type == kTlsRecordApplicationData)
    {
        ignored_tls_record_count_ = 0;
        plaintext_buffer_.append(plaintext.content, ec);
        if (ec)
        {
            return 0;
        }
        if (!plaintext_buffer_.empty())
        {
            return plaintext_buffer_.copy_to(output);
        }
        return std::nullopt;
    }

    if (plaintext.inner_type == kTlsRecordHandshake)
    {
        post_handshake_buffer_.append(plaintext.content, ec);
        if (ec)
        {
            return 0;
        }
        process_post_handshake_messages(ec);
        if (ec)
        {
            return 0;
        }
        return std::nullopt;
    }

    if (plaintext.inner_type == kTlsRecordAlert)
    {
        const bool close_notify = plaintext.content.size() == 2 && plaintext.content[0] == 1 && plaintext.content[1] == 0;
        if (close_notify)
        {
            receive_mode_ = receive_mode::kClosed;
            return 0;
        }
        ec = boost::system::errc::make_error_code(boost::system::errc::connection_aborted);
        return 0;
    }

    ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
    return 0;
}

boost::asio::awaitable<std::size_t> reality_stream::read_tls(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    for (;;)
    {
        auto record = co_await read_tls_record(ec);
        if (ec)
        {
            if (ec == boost::asio::error::eof)
            {
                receive_mode_ = receive_mode::kClosed;
            }
            co_return 0;
        }

        if (record->header[0] == kTlsRecordChangeCipherSpec)
        {
            if (++ignored_tls_record_count_ > 3)
            {
                ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
                co_return 0;
            }
            continue;
        }
        if (record->header[0] != kTlsRecordApplicationData || record->header[1] != 0x03 || record->header[2] != 0x03)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
            co_return 0;
        }

        const auto plaintext = receive_key_.open(record->header, record->payload, ec);
        if (ec)
        {
            co_return 0;
        }

        const auto result = process_decrypted_record(plaintext, output, ec);
        if (result)
        {
            co_return *result;
        }
    }
}

boost::asio::awaitable<void> reality_stream::write_tls_records(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    std::size_t offset = 0;
    while (offset != input.size())
    {
        const auto chunk_size = std::min(kMaxTlsPlaintext, input.size() - offset);
        const auto record = send_key_.seal(kTlsRecordApplicationData, input.subspan(offset, chunk_size), ec);
        if (ec)
        {
            co_return;
        }

        co_await tcp_.write(record, ec);
        if (ec)
        {
            co_return;
        }
        offset += chunk_size;
    }
}

boost::asio::awaitable<void> reality_stream::write(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    if (send_mode_ == send_mode::kRaw)
    {
        co_await tcp_.write(input, ec);
        co_return;
    }
    if (send_mode_ != send_mode::kTls)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::state_not_recoverable);
        co_return;
    }

    co_await write_tls_records(input, ec);
}

boost::asio::awaitable<void> reality_stream::shutdown_send(boost::system::error_code& ec)
{
    if (send_mode_ == send_mode::kClosed)
    {
        co_return;
    }
    if (send_mode_ == send_mode::kSwitchingToRaw)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_in_progress);
        co_return;
    }

    if (send_mode_ == send_mode::kTls)
    {
        constexpr std::array<std::uint8_t, 2> kCloseNotify{1, 0};
        const auto record = send_key_.seal(kTlsRecordAlert, kCloseNotify, ec);
        if (!ec)
        {
            co_await tcp_.write(record, ec);
        }
    }

    send_mode_ = send_mode::kClosed;
    boost::system::error_code shutdown_ec;
    tcp_.shutdown_send(shutdown_ec);
    if (!ec)
    {
        ec = shutdown_ec;
    }
}

void reality_stream::switch_receive_to_raw(boost::system::error_code& ec)
{
    if (receive_mode_ != receive_mode::kTls || !plaintext_buffer_.empty() || !post_handshake_buffer_.empty())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_permitted);
        return;
    }

    receive_mode_ = receive_mode::kRaw;
    spdlog::info("{} reality receive direction switched to raw", session_id_);
}

boost::asio::awaitable<void> reality_stream::write_final_tls_and_switch_to_raw(std::span<const std::uint8_t> final_plaintext,
                                                                               boost::system::error_code& ec)
{
    if (send_mode_ != send_mode::kTls)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_permitted);
        co_return;
    }

    send_mode_ = send_mode::kSwitchingToRaw;
    co_await write_tls_records(final_plaintext, ec);
    if (ec)
    {
        send_mode_ = send_mode::kClosed;
        co_return;
    }

    send_mode_ = send_mode::kRaw;
    spdlog::info("{} reality send direction switched to raw", session_id_);
}

void reality_stream::process_post_handshake_messages(boost::system::error_code& ec)
{
    while (post_handshake_buffer_.size() >= 4)
    {
        const auto message_length = handshake_message_length(post_handshake_buffer_.data());
        if (message_length > 1U << 20)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
            return;
        }
        if (post_handshake_buffer_.size() < message_length)
        {
            return;
        }

        const auto message_type = post_handshake_buffer_.data()[0];
        post_handshake_buffer_.consume(message_length);
        if (message_type == 4)
        {
            continue;
        }
        if (message_type == 24)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
            return;
        }

        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return;
    }
}

void reality_stream::shutdown() noexcept
{
    receive_mode_ = receive_mode::kClosed;
    send_mode_ = send_mode::kClosed;
    tcp_.shutdown();
}

}    // namespace rv::reality

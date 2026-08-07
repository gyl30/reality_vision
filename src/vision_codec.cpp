#include "vision_codec.hpp"

#include "crypto.hpp"

#include <boost/system/errc.hpp>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <span>
#include <vector>

namespace rv::vision
{
namespace
{

std::uint32_t uniform_below(std::uint32_t bound, boost::system::error_code& ec)
{
    if (bound == 0)
    {
        return 0;
    }
    const auto threshold = (-bound) % bound;
    for (;;)
    {
        std::array<std::uint8_t, 4> bytes{};
        crypto::random_bytes(bytes, ec);
        if (ec)
        {
            return 0;
        }
        const auto value = static_cast<std::uint32_t>(bytes[0]) << 24U | static_cast<std::uint32_t>(bytes[1]) << 16U |
                           static_cast<std::uint32_t>(bytes[2]) << 8U | static_cast<std::uint32_t>(bytes[3]);
        if (value >= threshold)
        {
            return value % bound;
        }
    }
}

std::size_t padding_length(std::size_t content_length, bool long_padding, boost::system::error_code& ec)
{
    std::size_t result = 0;
    if (long_padding && content_length < 900)
    {
        result = uniform_below(500, ec) + 900 - content_length;
    }
    else
    {
        result = uniform_below(256, ec);
    }
    if (ec)
    {
        return 0;
    }
    const auto maximum = content_length <= xray_buffer_size - full_header_size ? xray_buffer_size - full_header_size - content_length : 0;
    return std::min(result, maximum);
}

std::optional<std::size_t> find_server_hello_record(std::span<const std::uint8_t> input)
{
    constexpr std::array<std::uint8_t, 3> prefix{0x16, 0x03, 0x03};
    for (std::size_t offset = 0; offset + 6 <= input.size(); ++offset)
    {
        if (std::equal(prefix.begin(), prefix.end(), input.begin() + static_cast<std::ptrdiff_t>(offset)) && input[offset + 5] == 0x02)
        {
            return offset;
        }
    }
    return std::nullopt;
}

}    // namespace

boost::system::error_code decode_header(std::span<const std::uint8_t> header,
                                        const bool contains_user_id,
                                        std::span<const std::uint8_t, user_id_size> expected_user_id,
                                        frame_header& output)
{
    using boost::system::errc::make_error_code;

    const auto required = contains_user_id ? full_header_size : short_header_size;
    if (header.size() != required)
    {
        return make_error_code(boost::system::errc::bad_message);
    }

    const auto offset = contains_user_id ? user_id_size : 0;
    if (contains_user_id && !std::equal(expected_user_id.begin(), expected_user_id.end(), header.begin()))
    {
        return make_error_code(boost::system::errc::permission_denied);
    }

    const auto command_value = header[offset];
    if (command_value > static_cast<std::uint8_t>(command::direct))
    {
        return make_error_code(boost::system::errc::bad_message);
    }

    frame_header decoded{
        .frame_command = static_cast<command>(command_value),
        .content_length =
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(header[offset + 1]) << 8U | static_cast<std::uint16_t>(header[offset + 2])),
        .padding_length =
            static_cast<std::uint16_t>(static_cast<std::uint16_t>(header[offset + 3]) << 8U | static_cast<std::uint16_t>(header[offset + 4])),
    };
    if (required + static_cast<std::size_t>(decoded.content_length) + static_cast<std::size_t>(decoded.padding_length) > xray_buffer_size)
    {
        return make_error_code(boost::system::errc::message_size);
    }

    output = decoded;
    return {};
}

std::vector<std::uint8_t> encode_frame(command frame_command,
                                       std::optional<std::span<const std::uint8_t, user_id_size>> user_id,
                                       std::span<const std::uint8_t> content,
                                       bool long_padding,
                                       boost::system::error_code& ec)
{
    const auto header_size = user_id ? full_header_size : short_header_size;
    if (content.size() > xray_buffer_size - header_size || content.size() > std::numeric_limits<std::uint16_t>::max())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }
    const auto padding = padding_length(content.size(), long_padding, ec);
    if (ec)
    {
        return {};
    }

    std::vector<std::uint8_t> output;
    output.reserve(header_size + content.size() + padding);
    if (user_id)
    {
        output.insert(output.end(), user_id->begin(), user_id->end());
    }
    output.push_back(static_cast<std::uint8_t>(frame_command));
    output.push_back(static_cast<std::uint8_t>(content.size() >> 8U));
    output.push_back(static_cast<std::uint8_t>(content.size()));
    output.push_back(static_cast<std::uint8_t>(padding >> 8U));
    output.push_back(static_cast<std::uint8_t>(padding));
    output.insert(output.end(), content.begin(), content.end());
    output.resize(output.size() + padding, 0);
    return output;
}

namespace
{

inline constexpr std::size_t maximum_tls_record_payload = (1UL << 14U) + 256UL;

bool is_tls_record_header(const std::array<std::uint8_t, 5>& header, const bool first_record) noexcept
{
    const auto type = header[0];
    const bool valid_type = first_record ? type == 0x16 : type == 0x14 || type == 0x15 || type == 0x16 || type == 0x17;
    if (!valid_type || header[1] != 0x03 || header[2] < 0x01 || header[2] > 0x03)
    {
        return false;
    }

    const auto length = static_cast<std::size_t>(header[3]) << 8U | static_cast<std::size_t>(header[4]);
    return length <= maximum_tls_record_payload && (!first_record || length != 0);
}

bool server_hello_supports_direct(const std::span<const std::uint8_t> record)
{
    if (record.size() < 46)
    {
        return false;
    }

    const auto session_id_length = static_cast<std::size_t>(record[43]);
    const auto cipher_offset = 44 + session_id_length;
    if (cipher_offset + 2 > record.size())
    {
        return false;
    }

    const auto cipher = static_cast<std::uint16_t>(record[cipher_offset]) << 8U | static_cast<std::uint16_t>(record[cipher_offset + 1]);
    constexpr std::array<std::uint8_t, 6> tls13_version_extension{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    const bool has_tls13 = std::search(record.begin(), record.end(), tls13_version_extension.begin(), tls13_version_extension.end()) != record.end();
    return has_tls13 && cipher >= 0x1301 && cipher <= 0x1304;
}

}    // namespace

void client_tls_record_tracker::disable_tracking() noexcept
{
    if (kind_ == client_stream_kind::undecided)
    {
        kind_ = client_stream_kind::non_tls;
    }
    else
    {
        tracking_failed_ = true;
    }
    phase_ = phase::disabled;
}

bool client_tls_record_tracker::parse_record_header() noexcept
{
    if (!is_tls_record_header(header_, first_record_))
    {
        disable_tracking();
        return false;
    }

    record_type_ = header_[0];
    remaining_payload_ = static_cast<std::size_t>(header_[3]) << 8U | static_cast<std::size_t>(header_[4]);
    header_size_ = 0;
    phase_ = phase::payload;
    return true;
}

bool client_tls_record_tracker::consume_record_header(const std::span<const std::uint8_t> input, std::size_t& position) noexcept
{
    const auto count = std::min(header_.size() - header_size_, input.size() - position);
    std::copy_n(input.begin() + static_cast<std::ptrdiff_t>(position), count, header_.begin() + static_cast<std::ptrdiff_t>(header_size_));
    header_size_ += count;
    position += count;

    if (header_size_ != header_.size())
    {
        return false;
    }
    return parse_record_header();
}

bool client_tls_record_tracker::detect_client_hello(const std::span<const std::uint8_t> input, std::size_t& position) noexcept
{
    if (!first_record_ || kind_ != client_stream_kind::undecided)
    {
        return true;
    }
    if (position == input.size())
    {
        return false;
    }
    if (input[position] != 0x01)
    {
        disable_tracking();
        return false;
    }

    kind_ = client_stream_kind::tls;
    ++position;
    --remaining_payload_;
    return true;
}

client_tls_observation client_tls_record_tracker::observe(const std::span<const std::uint8_t> input) noexcept
{
    client_tls_observation observation{
        .kind = kind_,
        .encrypted_record_end_offset = std::nullopt,
        .tracking_failed = tracking_failed_,
    };

    if (phase_ == phase::disabled || input.empty())
    {
        return observation;
    }

    std::size_t position = 0;
    while (position != input.size())
    {
        if (phase_ == phase::header && !consume_record_header(input, position))
        {
            break;
        }
        if (phase_ != phase::payload || !detect_client_hello(input, position))
        {
            break;
        }

        const auto count = std::min(remaining_payload_, input.size() - position);
        position += count;
        remaining_payload_ -= count;
        if (remaining_payload_ != 0)
        {
            break;
        }

        const auto completed_record_type = record_type_;
        first_record_ = false;
        phase_ = phase::header;

        if (kind_ == client_stream_kind::tls && completed_record_type == 0x17)
        {
            observation.encrypted_record_end_offset = position;
            break;
        }
    }

    observation.kind = kind_;
    observation.tracking_failed = tracking_failed_;
    return observation;
}

void server_hello_tracker::observe(std::span<const std::uint8_t> input)
{
    if (done_ || input.empty())
    {
        return;
    }
    if (input.size() > (64UL * 1024U) - buffer_.size())
    {
        done_ = true;
        return;
    }
    buffer_.insert(buffer_.end(), input.begin(), input.end());
    evaluate_server_hello();
}

bool server_hello_tracker::prepare_server_hello_record()
{
    if (!record_length_)
    {
        const auto offset = find_server_hello_record(buffer_);
        if (!offset)
        {
            if (buffer_.size() > 5)
            {
                buffer_.erase(buffer_.begin(), buffer_.end() - 5);
            }
            return false;
        }

        if (*offset != 0)
        {
            buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(*offset));
        }
        if (buffer_.size() < 5)
        {
            return false;
        }

        record_length_ = 5 + (static_cast<std::size_t>(buffer_[3]) << 8U | static_cast<std::size_t>(buffer_[4]));
        if (*record_length_ > 64UL * 1024U)
        {
            done_ = true;
            return false;
        }
    }

    return buffer_.size() >= *record_length_;
}

void server_hello_tracker::evaluate_server_hello()
{
    if (!prepare_server_hello_record())
    {
        return;
    }

    done_ = true;
    const auto record = std::span<const std::uint8_t>(buffer_.data(), *record_length_);
    direct_supported_ = server_hello_supports_direct(record);
}

}    // namespace rv::vision

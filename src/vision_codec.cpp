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
    const auto threshold = static_cast<std::uint32_t>(-bound) % bound;
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

std::optional<std::size_t> find_server_hello(std::span<const std::uint8_t> input)
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

bool decode_header(std::span<const std::uint8_t> header,
                   bool contains_user_id,
                   std::span<const std::uint8_t, user_id_size> expected_user_id,
                   frame_header& output,
                   boost::system::error_code& ec)
{
    ec.clear();
    const auto required = contains_user_id ? full_header_size : short_header_size;
    if (header.size() != required)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return false;
    }
    const auto offset = contains_user_id ? user_id_size : 0;
    if (contains_user_id && !std::equal(expected_user_id.begin(), expected_user_id.end(), header.begin()))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::permission_denied);
        return false;
    }
    const auto command_value = header[offset];
    if (command_value > static_cast<std::uint8_t>(command::direct))
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        return false;
    }

    output = {
        static_cast<command>(command_value),
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(header[offset + 1]) << 8U | static_cast<std::uint16_t>(header[offset + 2])),
        static_cast<std::uint16_t>(static_cast<std::uint16_t>(header[offset + 3]) << 8U | static_cast<std::uint16_t>(header[offset + 4])),
    };
    if (required + static_cast<std::size_t>(output.content_length) + static_cast<std::size_t>(output.padding_length) > xray_buffer_size)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return false;
    }
    return true;
}

std::vector<std::uint8_t> encode_frame(command frame_command,
                                       std::optional<std::span<const std::uint8_t, user_id_size>> user_id,
                                       std::span<const std::uint8_t> content,
                                       bool long_padding,
                                       boost::system::error_code& ec)
{
    ec.clear();
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

bool contains_tls_client_hello(std::span<const std::uint8_t> input) noexcept
{
    for (std::size_t offset = 0; offset + 6 <= input.size(); ++offset)
    {
        if (input[offset] == 0x16 && input[offset + 1] == 0x03 && input[offset + 5] == 0x01)
        {
            return true;
        }
    }
    return false;
}

bool starts_tls13_application_data(std::span<const std::uint8_t> input) noexcept
{
    return input.size() >= 3 && input[0] == 0x17 && input[1] == 0x03 && input[2] == 0x03;
}

bool consists_of_complete_tls13_application_records(std::span<const std::uint8_t> input) noexcept
{
    std::size_t position = 0;
    while (position != input.size())
    {
        if (input.size() - position < 5 || input[position] != 0x17 || input[position + 1] != 0x03 || input[position + 2] != 0x03)
        {
            return false;
        }
        const auto length = static_cast<std::size_t>(input[position + 3]) << 8U | static_cast<std::size_t>(input[position + 4]);
        position += 5;
        if (length > input.size() - position)
        {
            return false;
        }
        position += length;
    }
    return !input.empty();
}

void server_hello_filter::observe(std::span<const std::uint8_t> input)
{
    if (done_ || input.empty())
    {
        return;
    }
    if (input.size() > 64U * 1024U - buffer_.size())
    {
        done_ = true;
        return;
    }
    buffer_.insert(buffer_.end(), input.begin(), input.end());
    evaluate();
}

void server_hello_filter::evaluate()
{
    if (!record_length_)
    {
        const auto offset = find_server_hello(buffer_);
        if (!offset)
        {
            if (buffer_.size() > 5)
            {
                buffer_.erase(buffer_.begin(), buffer_.end() - 5);
            }
            return;
        }
        if (*offset != 0)
        {
            buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(*offset));
        }
        if (buffer_.size() < 5)
        {
            return;
        }
        record_length_ = 5 + (static_cast<std::size_t>(buffer_[3]) << 8U | static_cast<std::size_t>(buffer_[4]));
        if (*record_length_ > 64U * 1024U)
        {
            done_ = true;
            return;
        }
    }
    if (buffer_.size() < *record_length_)
    {
        return;
    }

    done_ = true;
    const auto record = std::span<const std::uint8_t>(buffer_.data(), *record_length_);
    if (record.size() < 46)
    {
        return;
    }
    const auto session_id_length = static_cast<std::size_t>(record[43]);
    const auto cipher_offset = 44 + session_id_length;
    if (cipher_offset + 2 > record.size())
    {
        return;
    }
    const auto cipher = static_cast<std::uint16_t>(record[cipher_offset]) << 8U | static_cast<std::uint16_t>(record[cipher_offset + 1]);
    constexpr std::array<std::uint8_t, 6> tls13_version_extension{0x00, 0x2b, 0x00, 0x02, 0x03, 0x04};
    const auto has_tls13 = std::search(record.begin(), record.end(), tls13_version_extension.begin(), tls13_version_extension.end()) != record.end();
    direct_supported_ = has_tls13 && cipher >= 0x1301 && cipher <= 0x1304;
}

}    // namespace rv::vision

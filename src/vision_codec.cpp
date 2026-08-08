#include "vision_codec.hpp"

#include "byte_order.hpp"
#include "byte_reader.hpp"
#include "byte_writer.hpp"
#include "crypto.hpp"
#include "tls_constants.hpp"

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

inline constexpr std::size_t kMaximumServerHelloRecordSize = 64UL * 1024U;
inline constexpr std::uint16_t kFirstDirectCipher = 0x1301;
inline constexpr std::uint16_t kLastDirectCipher = 0x1304;
inline constexpr std::uint16_t kMinimumRecordVersion = 0x0301;
inline constexpr std::size_t kLongPaddingThreshold = 900;
inline constexpr std::uint32_t kLongPaddingRandomRange = 500;
inline constexpr std::uint32_t kShortPaddingRandomRange = 256;

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
        const auto value = core::read_be32(bytes.data());
        if (value >= threshold)
        {
            return value % bound;
        }
    }
}

std::size_t padding_length(std::size_t content_length, bool long_padding, boost::system::error_code& ec)
{
    std::size_t result = 0;
    if (long_padding && content_length < kLongPaddingThreshold)
    {
        result = uniform_below(kLongPaddingRandomRange, ec) + kLongPaddingThreshold - content_length;
    }
    else
    {
        result = uniform_below(kShortPaddingRandomRange, ec);
    }
    if (ec)
    {
        return 0;
    }
    const auto maximum = content_length <= kXrayBufferSize - kFullHeaderSize ? kXrayBufferSize - kFullHeaderSize - content_length : 0;
    return std::min(result, maximum);
}

std::optional<std::size_t> find_server_hello_record(std::span<const std::uint8_t> input)
{
    for (std::size_t offset = 0; offset + tls::kRecordHeaderSize + 1 <= input.size(); ++offset)
    {
        if (input[offset] == tls::kRecordHandshake && core::read_be16(input.data() + offset + 1) == tls::kLegacyVersion &&
            input[offset + tls::kRecordHeaderSize] == tls::kHandshakeServerHello)
        {
            return offset;
        }
    }
    return std::nullopt;
}

}    // namespace

boost::system::error_code decode_header(std::span<const std::uint8_t> header,
                                        const bool contains_user_id,
                                        std::span<const std::uint8_t, kUserIdSize> expected_user_id,
                                        frame_header& output)
{
    using boost::system::errc::make_error_code;

    const auto required = contains_user_id ? kFullHeaderSize : kShortHeaderSize;
    if (header.size() != required)
    {
        return make_error_code(boost::system::errc::bad_message);
    }

    const auto offset = contains_user_id ? kUserIdSize : 0;
    if (contains_user_id && !std::equal(expected_user_id.begin(), expected_user_id.end(), header.begin()))
    {
        return make_error_code(boost::system::errc::permission_denied);
    }

    const auto command_value = header[offset];
    if (command_value > static_cast<std::uint8_t>(command::kDirect))
    {
        return make_error_code(boost::system::errc::bad_message);
    }

    frame_header decoded{
        .frame_command = static_cast<command>(command_value),
        .content_length = core::read_be16(header.data() + offset + 1),
        .padding_length = core::read_be16(header.data() + offset + 3),
    };
    if (required + static_cast<std::size_t>(decoded.content_length) + static_cast<std::size_t>(decoded.padding_length) > kXrayBufferSize)
    {
        return make_error_code(boost::system::errc::message_size);
    }

    output = decoded;
    return {};
}

std::vector<std::uint8_t> encode_frame(command frame_command,
                                       std::optional<std::span<const std::uint8_t, kUserIdSize>> user_id,
                                       std::span<const std::uint8_t> content,
                                       bool long_padding,
                                       boost::system::error_code& ec)
{
    const auto header_size = user_id ? kFullHeaderSize : kShortHeaderSize;
    if (content.size() > kXrayBufferSize - kFullHeaderSize || content.size() > std::numeric_limits<std::uint16_t>::max())
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
    core::append_be16(output, static_cast<std::uint16_t>(content.size()));
    core::append_be16(output, static_cast<std::uint16_t>(padding));
    output.insert(output.end(), content.begin(), content.end());
    output.resize(output.size() + padding, 0);
    return output;
}

namespace
{

bool is_tls_record_header(const std::array<std::uint8_t, tls::kRecordHeaderSize>& header, const bool first_record) noexcept
{
    const auto type = header[0];
    const bool valid_type = first_record ? type == tls::kRecordHandshake
                                         : type == tls::kRecordChangeCipherSpec || type == tls::kRecordAlert || type == tls::kRecordHandshake ||
                                               type == tls::kRecordApplicationData;
    const auto version = core::read_be16(header.data() + 1);
    if (!valid_type || version < kMinimumRecordVersion || version > tls::kLegacyVersion)
    {
        return false;
    }

    const auto length = static_cast<std::size_t>(core::read_be16(header.data() + 3));
    return length <= tls::kMaximumCiphertextSize && (!first_record || length != 0);
}

bool extensions_support_tls13(const std::span<const std::uint8_t> extensions)
{
    core::byte_reader reader(extensions);
    bool supported = false;
    while (!reader.empty())
    {
        std::uint16_t type = 0;
        std::uint16_t length = 0;
        if (!reader.read_u16(type) || !reader.read_u16(length))
        {
            return false;
        }

        const auto data = reader.read_bytes(length);
        if (!data)
        {
            return false;
        }
        if (type == tls::kExtensionSupportedVersions)
        {
            supported = data->size() == 2 && core::read_be16(data->data()) == tls::kTls13Version;
        }
    }
    return supported;
}

bool server_hello_supports_direct(const std::span<const std::uint8_t> record)
{
    if (record.size() < tls::kRecordHeaderSize)
    {
        return false;
    }

    core::byte_reader record_reader(record.subspan(tls::kRecordHeaderSize));
    std::uint8_t handshake_type = 0;
    std::uint32_t handshake_length = 0;
    if (!record_reader.read_u8(handshake_type) || !record_reader.read_u24(handshake_length) || handshake_type != tls::kHandshakeServerHello)
    {
        return false;
    }

    const auto body = record_reader.read_bytes(handshake_length);
    if (!body)
    {
        return false;
    }

    core::byte_reader reader(*body);
    std::uint16_t legacy_version = 0;
    std::uint8_t session_id_length = 0;
    std::uint16_t cipher = 0;
    std::uint8_t compression = 0;
    std::uint16_t extensions_length = 0;
    if (!reader.read_u16(legacy_version) || legacy_version != tls::kLegacyVersion || !reader.skip(tls::kRandomSize) ||
        !reader.read_u8(session_id_length) || !reader.skip(session_id_length) || !reader.read_u16(cipher) || !reader.read_u8(compression) ||
        compression != tls::kNullCompressionMethod || !reader.read_u16(extensions_length))
    {
        return false;
    }

    const auto extensions = reader.read_bytes(extensions_length);
    if (!extensions || !reader.empty())
    {
        return false;
    }

    return cipher >= kFirstDirectCipher && cipher <= kLastDirectCipher && extensions_support_tls13(*extensions);
}

}    // namespace

void client_tls_record_tracker::disable_tracking() noexcept
{
    if (kind_ == client_stream_kind::kUndecided)
    {
        kind_ = client_stream_kind::kNonTls;
    }
    else
    {
        tracking_failed_ = true;
    }
    phase_ = phase::kDisabled;
}

bool client_tls_record_tracker::parse_record_header() noexcept
{
    if (!is_tls_record_header(header_, first_record_))
    {
        disable_tracking();
        return false;
    }

    record_type_ = header_[0];
    remaining_payload_ = static_cast<std::size_t>(core::read_be16(header_.data() + 3));
    header_size_ = 0;
    phase_ = phase::kPayload;
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
    if (!first_record_ || kind_ != client_stream_kind::kUndecided)
    {
        return true;
    }
    if (position == input.size())
    {
        return false;
    }
    if (input[position] != tls::kHandshakeClientHello)
    {
        disable_tracking();
        return false;
    }

    kind_ = client_stream_kind::kTls;
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

    if (phase_ == phase::kDisabled || input.empty())
    {
        return observation;
    }

    std::size_t position = 0;
    while (position != input.size())
    {
        if (phase_ == phase::kHeader && !consume_record_header(input, position))
        {
            break;
        }
        if (phase_ != phase::kPayload || !detect_client_hello(input, position))
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
        phase_ = phase::kHeader;

        if (kind_ == client_stream_kind::kTls && completed_record_type == tls::kRecordApplicationData)
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
    if (input.size() > kMaximumServerHelloRecordSize - buffer_.size())
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
            if (buffer_.size() > tls::kRecordHeaderSize)
            {
                buffer_.erase(buffer_.begin(), buffer_.end() - static_cast<std::ptrdiff_t>(tls::kRecordHeaderSize));
            }
            return false;
        }

        if (*offset != 0)
        {
            buffer_.erase(buffer_.begin(), buffer_.begin() + static_cast<std::ptrdiff_t>(*offset));
        }
        if (buffer_.size() < tls::kRecordHeaderSize)
        {
            return false;
        }

        record_length_ = tls::kRecordHeaderSize + static_cast<std::size_t>(core::read_be16(buffer_.data() + 3));
        if (*record_length_ > kMaximumServerHelloRecordSize)
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

#include <limits>
#include <algorithm>
#include <string>
#include <variant>
#include <type_traits>

#include <boost/system/errc.hpp>

#include "byte_order.hpp"
#include "byte_writer.hpp"
#include "xudp_codec.hpp"

namespace rv::xudp
{
namespace
{

constexpr std::uint8_t kStatusNew = 0x01;
constexpr std::uint8_t kStatusKeep = 0x02;
constexpr std::uint8_t kStatusKeepAlive = 0x04;
constexpr std::uint8_t kOptionData = 0x01;
constexpr std::uint8_t kNetworkUdp = 0x02;
constexpr std::uint8_t kIpv4AddressType = 0x01;
constexpr std::uint8_t kDomainAddressType = 0x02;
constexpr std::uint8_t kIpv6AddressType = 0x03;
constexpr std::size_t kMinimumMetadataSize = 4;
constexpr std::size_t kStatusOffset = 2;
constexpr std::size_t kOptionOffset = 3;
constexpr std::size_t kNetworkOffset = 4;
constexpr std::size_t kMaximumDomainLength = std::numeric_limits<std::uint8_t>::max();

// Mux.Cool 地址：端口在前，随后是地址类型与地址。
void append_address_port(const endpoint& value, std::vector<std::uint8_t>& output, boost::system::error_code& ec)
{
    core::append_be16(output, value.port);
    std::visit(
        [&output, &ec](const auto& address)
        {
            using type = std::decay_t<decltype(address)>;
            if constexpr (std::is_same_v<type, net::ipv4_address>)
            {
                output.push_back(kIpv4AddressType);
                output.insert(output.end(), address.bytes.begin(), address.bytes.end());
            }
            else if constexpr (std::is_same_v<type, net::domain_address>)
            {
                if (address.name.empty() || address.name.size() > kMaximumDomainLength)
                {
                    ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
                    return;
                }
                output.push_back(kDomainAddressType);
                output.push_back(static_cast<std::uint8_t>(address.name.size()));
                output.insert(output.end(), address.name.begin(), address.name.end());
            }
            else
            {
                output.push_back(kIpv6AddressType);
                output.insert(output.end(), address.bytes.begin(), address.bytes.end());
            }
        },
        value.address);
}

template <typename Bytes>
bool take_bytes(std::span<const std::uint8_t>& input, Bytes& output)
{
    if (input.size() < output.size())
    {
        return false;
    }
    std::copy_n(input.begin(), output.size(), output.begin());
    input = input.subspan(output.size());
    return true;
}

std::optional<endpoint> parse_address_port(std::span<const std::uint8_t> input)
{
    if (input.size() < 3)
    {
        return std::nullopt;
    }
    endpoint output;
    output.port = core::read_be16(input.data());
    const auto type = input[2];
    input = input.subspan(3);
    if (type == kIpv4AddressType)
    {
        net::ipv4_address address;
        if (!take_bytes(input, address.bytes))
        {
            return std::nullopt;
        }
        output.address = address;
        return output;
    }
    if (type == kIpv6AddressType)
    {
        net::ipv6_address address;
        if (!take_bytes(input, address.bytes))
        {
            return std::nullopt;
        }
        output.address = address;
        return output;
    }
    if (type == kDomainAddressType && !input.empty() && input[0] != 0 && input.size() >= 1U + input[0])
    {
        output.address = net::domain_address{std::string(input.begin() + 1, input.begin() + 1 + input[0])};
        return output;
    }
    return std::nullopt;
}

std::vector<std::uint8_t> encode_frame(const std::uint8_t status,
                                       const endpoint& destination,
                                       const global_id* id,
                                       const std::span<const std::uint8_t> payload,
                                       boost::system::error_code& ec)
{
    if (payload.empty())
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }
    if (payload.size() > kMaximumPayloadSize)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::message_size);
        return {};
    }

    std::vector<std::uint8_t> output(kFrameLengthSize);
    core::append_be16(output, 0);
    output.push_back(status);
    output.push_back(kOptionData);
    output.push_back(kNetworkUdp);
    append_address_port(destination, output, ec);
    if (ec)
    {
        return {};
    }
    if (id != nullptr)
    {
        output.insert(output.end(), id->begin(), id->end());
    }

    const auto metadata_size = output.size() - kFrameLengthSize;
    output[0] = static_cast<std::uint8_t>(metadata_size >> 8U);
    output[1] = static_cast<std::uint8_t>(metadata_size);
    core::append_be16(output, static_cast<std::uint16_t>(payload.size()));
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

}    // namespace

std::vector<std::uint8_t> encode_new_frame(const endpoint& destination,
                                           const global_id& id,
                                           const std::span<const std::uint8_t> payload,
                                           boost::system::error_code& ec)
{
    return encode_frame(kStatusNew, destination, &id, payload, ec);
}

std::vector<std::uint8_t> encode_keep_frame(const endpoint& destination, const std::span<const std::uint8_t> payload, boost::system::error_code& ec)
{
    return encode_frame(kStatusKeep, destination, nullptr, payload, ec);
}

frame_metadata parse_frame_metadata(const std::span<const std::uint8_t> metadata, boost::system::error_code& ec)
{
    frame_metadata output;
    if (metadata.size() < kMinimumMetadataSize)
    {
        return output;
    }

    output.has_data = (metadata[kOptionOffset] & kOptionData) != 0;
    const auto status = metadata[kStatusOffset];
    if (status == kStatusKeepAlive)
    {
        output.kind = frame_kind::kDiscard;
        return output;
    }
    if (status != kStatusKeep)
    {
        return output;
    }

    output.kind = frame_kind::kData;
    if (metadata.size() > kNetworkOffset && metadata[kNetworkOffset] == kNetworkUdp)
    {
        output.source = parse_address_port(metadata.subspan(kNetworkOffset + 1));
        if (!output.source)
        {
            ec = boost::system::errc::make_error_code(boost::system::errc::bad_message);
        }
    }
    return output;
}

}    // namespace rv::xudp

#include <limits>
#include <cstdint>
#include <variant>
#include <string_view>
#include <type_traits>

#include <boost/system/errc.hpp>

#include "byte_writer.hpp"
#include "vless_header.hpp"

namespace rv::vless
{
namespace
{

constexpr std::uint8_t kVersion = 0x00;
constexpr std::uint8_t kTcpCommand = 0x01;
constexpr std::uint8_t kUdpCommand = 0x02;
constexpr std::uint8_t kMuxCommand = 0x03;
constexpr std::uint8_t kIpv4AddressType = 0x01;
constexpr std::uint8_t kDomainAddressType = 0x02;
constexpr std::uint8_t kIpv6AddressType = 0x03;
constexpr std::uint8_t kNoAddonLength = 0x00;
constexpr std::uint8_t kFlowFieldTag = 0x0a;
constexpr std::size_t kMaximumDomainLength = std::numeric_limits<std::uint8_t>::max();
constexpr std::size_t kRequestReserveSize = 64;
constexpr std::string_view kVisionFlowName = "xtls-rprx-vision";
constexpr std::size_t kVisionAddonLength = 2 + kVisionFlowName.size();
static_assert(kVisionFlowName.size() <= std::numeric_limits<std::uint8_t>::max());
static_assert(kVisionAddonLength <= std::numeric_limits<std::uint8_t>::max());

void append_vision_flow_addon(std::vector<std::uint8_t>& output)
{
    output.push_back(static_cast<std::uint8_t>(kVisionAddonLength));
    output.push_back(kFlowFieldTag);
    output.push_back(static_cast<std::uint8_t>(kVisionFlowName.size()));
    output.insert(output.end(), kVisionFlowName.begin(), kVisionFlowName.end());
}

void append_destination(const client_config& configuration, std::vector<std::uint8_t>& output, boost::system::error_code& ec)
{
    core::append_be16(output, configuration.destination_port);
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
                if (address.name.empty() || address.name.size() > kMaximumDomainLength || address.name.find('\0') != std::string::npos)
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
        configuration.destination);
}

std::vector<std::uint8_t> encode_request(const client_config& configuration, const std::uint8_t command, boost::system::error_code& ec)
{
    if (configuration.destination_port == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    std::vector<std::uint8_t> output;
    output.reserve(kRequestReserveSize);
    output.push_back(kVersion);
    output.insert(output.end(), configuration.user_id.begin(), configuration.user_id.end());

    if (command == kTcpCommand)
    {
        append_vision_flow_addon(output);
    }
    else
    {
        output.push_back(kNoAddonLength);
    }

    output.push_back(command);
    append_destination(configuration, output, ec);
    if (ec)
    {
        return {};
    }
    return output;
}

}    // namespace

std::vector<std::uint8_t> encode_tcp_request(const client_config& configuration, boost::system::error_code& ec)
{
    return encode_request(configuration, kTcpCommand, ec);
}

std::vector<std::uint8_t> encode_xudp_request(const std::array<std::uint8_t, kUserIdSize>& user_id)
{
    // Xray EncodeRequestHeader 对 Mux 命令不写目标地址，Mux.Cool 帧紧随请求头。
    std::vector<std::uint8_t> output;
    output.reserve(kRequestReserveSize);
    output.push_back(kVersion);
    output.insert(output.end(), user_id.begin(), user_id.end());
    append_vision_flow_addon(output);
    output.push_back(kMuxCommand);
    return output;
}

std::vector<std::uint8_t> encode_udp_request(const client_config& configuration, boost::system::error_code& ec)
{
    return encode_request(configuration, kUdpCommand, ec);
}

}    // namespace rv::vless

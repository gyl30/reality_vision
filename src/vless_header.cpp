#include "vless_header.hpp"

#include "byte_writer.hpp"

#include <boost/system/errc.hpp>

#include <cstdint>
#include <type_traits>
#include <variant>

namespace rv::vless
{
namespace
{

constexpr std::uint8_t kTcpCommand = 0x01;
constexpr std::uint8_t kUdpCommand = 0x02;

void append_destination(const client_config& configuration, std::vector<std::uint8_t>& output, boost::system::error_code& ec)
{
    core::append_be16(output, configuration.destination_port);
    std::visit(
        [&output, &ec](const auto& address)
        {
            using type = std::decay_t<decltype(address)>;
            if constexpr (std::is_same_v<type, ipv4_address>)
            {
                output.push_back(0x01);
                output.insert(output.end(), address.bytes.begin(), address.bytes.end());
            }
            else if constexpr (std::is_same_v<type, domain_address>)
            {
                if (address.name.empty() || address.name.size() > 255 || address.name.find('\0') != std::string::npos)
                {
                    ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
                    return;
                }
                output.push_back(0x02);
                output.push_back(static_cast<std::uint8_t>(address.name.size()));
                output.insert(output.end(), address.name.begin(), address.name.end());
            }
            else
            {
                output.push_back(0x03);
                output.insert(output.end(), address.bytes.begin(), address.bytes.end());
            }
        },
        configuration.destination);
}

std::vector<std::uint8_t> encode_request(const client_config& configuration,
                                         const std::uint8_t command,
                                         const bool vision_flow,
                                         boost::system::error_code& ec)
{
    ec.clear();
    if (configuration.destination_port == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    std::vector<std::uint8_t> output;
    output.reserve(64);
    output.push_back(0x00);
    output.insert(output.end(), configuration.user_id.begin(), configuration.user_id.end());

    if (vision_flow)
    {
        constexpr char kFlowName[] = "xtls-rprx-vision";
        output.push_back(18);
        output.push_back(0x0a);
        output.push_back(0x10);
        output.insert(output.end(), kFlowName, kFlowName + 16);
    }
    else
    {
        output.push_back(0x00);
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
    return encode_request(configuration, kTcpCommand, true, ec);
}

std::vector<std::uint8_t> encode_udp_request(const client_config& configuration, boost::system::error_code& ec)
{
    return encode_request(configuration, kUdpCommand, false, ec);
}

}    // namespace rv::vless

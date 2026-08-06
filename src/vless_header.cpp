#include "vless_header.hpp"

#include <boost/system/errc.hpp>

#include <cstddef>
#include <cstdint>
#include <type_traits>
#include <variant>

namespace rv::vless
{
namespace
{

void put_u16(std::uint16_t value, std::vector<std::uint8_t>& output)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

} // namespace

std::vector<std::uint8_t> encode_tcp_request(
    const client_config& config,
    boost::system::error_code& ec)
{
    ec.clear();
    if (config.destination_port == 0)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::invalid_argument);
        return {};
    }

    std::vector<std::uint8_t> output;
    output.reserve(64);
    output.push_back(0x00);
    output.insert(output.end(), config.user_id.begin(), config.user_id.end());

    if (config.selected_flow == flow::xtls_rprx_vision)
    {
        constexpr char name[] = "xtls-rprx-vision";
        output.push_back(18);
        output.push_back(0x0a);
        output.push_back(0x10);
        output.insert(output.end(), name, name + 16);
    }
    else
    {
        output.push_back(0);
    }

    output.push_back(0x01);
    put_u16(config.destination_port, output);
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
        config.destination);
    if (ec)
    {
        return {};
    }
    return output;
}

} // namespace rv::vless

#include "network_address.hpp"

#include <boost/asio/ip/address_v6.hpp>

#include <algorithm>
#include <string>
#include <type_traits>

namespace rv::net
{

std::string format_address_port(const address& value, const std::uint16_t port)
{
    const auto host = std::visit(
        [](const auto& item) -> std::string
        {
            using address_type = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<address_type, ipv4_address>)
            {
                return std::to_string(item.bytes[0]) + "." + std::to_string(item.bytes[1]) + "." + std::to_string(item.bytes[2]) + "." +
                       std::to_string(item.bytes[3]);
            }
            else if constexpr (std::is_same_v<address_type, ipv6_address>)
            {
                boost::asio::ip::address_v6::bytes_type bytes{};
                std::copy(item.bytes.begin(), item.bytes.end(), bytes.begin());
                return "[" + boost::asio::ip::address_v6(bytes).to_string() + "]";
            }
            else
            {
                return item.name;
            }
        },
        value);

    return host + ":" + std::to_string(port);
}

}    // namespace rv::net

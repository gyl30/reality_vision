#include <cstring>

#include <boost/asio/ip/address_v4.hpp>
#include <boost/asio/ip/address_v6.hpp>

#include "tun_lwip.hpp"

namespace rv::tun
{

boost::asio::ip::address lwip_to_address(const ip_addr_t& address)
{
    if (IP_IS_V4_VAL(address))
    {
        boost::asio::ip::address_v4::bytes_type bytes{};
        const auto raw = ip_2_ip4(&address)->addr;
        std::memcpy(bytes.data(), &raw, bytes.size());
        return boost::asio::ip::address_v4(bytes);
    }

    boost::asio::ip::address_v6::bytes_type bytes{};
    std::memcpy(bytes.data(), ip_2_ip6(&address)->addr, bytes.size());
    return boost::asio::ip::address_v6(bytes);
}

boost::asio::ip::udp::endpoint lwip_to_udp_endpoint(const ip_addr_t& address, const std::uint16_t port)
{
    return {lwip_to_address(address), port};
}

bool address_to_lwip(const boost::asio::ip::address& address, ip_addr_t& output)
{
    if (address.is_v4())
    {
        const auto bytes = address.to_v4().to_bytes();
        output.type = IPADDR_TYPE_V4;
        std::memcpy(&ip_2_ip4(&output)->addr, bytes.data(), bytes.size());
        return true;
    }
    if (address.is_v6())
    {
        const auto bytes = address.to_v6().to_bytes();
        output.type = IPADDR_TYPE_V6;
        std::memcpy(ip_2_ip6(&output)->addr, bytes.data(), bytes.size());
        return true;
    }
    return false;
}

std::vector<std::uint8_t> pbuf_to_vector(const pbuf* packet)
{
    std::vector<std::uint8_t> output;
    if (packet == nullptr)
    {
        return output;
    }

    output.reserve(packet->tot_len);
    for (auto* current = packet; current != nullptr; current = current->next)
    {
        const auto* data = static_cast<const std::uint8_t*>(current->payload);
        output.insert(output.end(), data, data + current->len);
    }
    return output;
}

}    // namespace rv::tun

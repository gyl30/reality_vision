#ifndef REALITY_VISION_TUN_LWIP_HPP
#define REALITY_VISION_TUN_LWIP_HPP

#include <cstdint>
#include <string>
#include <vector>

extern "C"
{
#include "lwip/ip.h"
#include "lwip/ip4.h"
#include "lwip/ip6.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/nd6.h"
#include "lwip/pbuf.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/priv/tcp_priv.h"
}

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/udp.hpp>

namespace rv::tun
{

[[nodiscard]] boost::asio::ip::address lwip_to_address(const ip_addr_t& address);
[[nodiscard]] boost::asio::ip::udp::endpoint lwip_to_udp_endpoint(const ip_addr_t& address, std::uint16_t port);
[[nodiscard]] bool address_to_lwip(const boost::asio::ip::address& address, ip_addr_t& output);
[[nodiscard]] std::vector<std::uint8_t> pbuf_to_vector(const pbuf* packet);

}    // namespace rv::tun

#endif    // REALITY_VISION_TUN_LWIP_HPP

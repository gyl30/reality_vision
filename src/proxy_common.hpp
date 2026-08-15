#ifndef REALITY_VISION_PROXY_COMMON_HPP
#define REALITY_VISION_PROXY_COMMON_HPP

#include <string>
#include <cstdint>
#include <optional>

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "reality_stream.hpp"
#include "network_address.hpp"
#include "vision_stream.hpp"
#include "vless_udp_stream.hpp"

namespace rv::app
{
struct config;
}    // namespace rv::app

namespace rv::proxy
{

struct target
{
    net::address destination;
    std::uint16_t port{};
};

[[nodiscard]] boost::asio::awaitable<std::optional<reality::reality_stream>> connect_reality(const app::config& configuration,
                                                                                             const std::string& session_id,
                                                                                             boost::system::error_code& ec);

[[nodiscard]] boost::asio::awaitable<std::optional<vision::vision_stream>> connect_vision(reality::reality_stream reality,
                                                                                           const app::config& configuration,
                                                                                           const target& destination,
                                                                                           const std::string& session_id,
                                                                                           boost::system::error_code& ec);

[[nodiscard]] boost::asio::awaitable<std::optional<vless::vless_udp_stream>> connect_udp(const app::config& configuration,
                                                                                          const target& destination,
                                                                                          const std::string& session_id,
                                                                                          boost::system::error_code& ec);

}    // namespace rv::proxy

#endif    // REALITY_VISION_PROXY_COMMON_HPP

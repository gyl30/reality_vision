#ifndef REALITY_VISION_PROXY_COMMON_HPP
#define REALITY_VISION_PROXY_COMMON_HPP

#include <chrono>
#include <string>
#include <cstdint>
#include <optional>

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "reality_stream.hpp"
#include "network_address.hpp"
#include "vision_stream.hpp"
#include "xudp_stream.hpp"

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

// 在 last_activity 之后持续 timeout 没有更新时返回；调用方用 || 与中继组合以取消空闲连接。
[[nodiscard]] boost::asio::awaitable<void> wait_until_idle(const std::chrono::steady_clock::time_point& last_activity,
                                                           std::chrono::seconds timeout);

[[nodiscard]] boost::asio::awaitable<std::optional<xudp::xudp_stream>> connect_xudp(const app::config& configuration,
                                                                                      const xudp::global_id& id,
                                                                                      const std::string& session_id,
                                                                                      boost::system::error_code& ec);

}    // namespace rv::proxy

#endif    // REALITY_VISION_PROXY_COMMON_HPP

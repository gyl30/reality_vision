#ifndef REALITY_VISION_PROXY_COMMON_HPP
#define REALITY_VISION_PROXY_COMMON_HPP

#include "network_address.hpp"
#include "reality_stream.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <exception>
#include <optional>
#include <string>
#include <string_view>

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

void session_exception(const std::string& session_id,
                       const std::exception_ptr& exception,
                       std::string_view session_kind = "session");

void log_service_exception(const std::string& service_id, const std::exception_ptr& exception);

}    // namespace rv::proxy

#endif    // REALITY_VISION_PROXY_COMMON_HPP

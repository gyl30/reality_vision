#include <chrono>
#include <string>
#include <utility>
#include <variant>

#include <boost/system/errc.hpp>
#include <boost/asio/this_coro.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>

#include "config.hpp"
#include "proxy_common.hpp"
#include "reality_config.hpp"
#include "tcp_byte_stream.hpp"
#include "vless_header.hpp"
#include "vless_stream.hpp"

namespace rv::proxy
{
namespace
{

constexpr auto kUpstreamHandshakeTimeout = std::chrono::seconds(60);

}    // namespace

boost::asio::awaitable<std::optional<reality::reality_stream>> connect_reality(const app::config& configuration,
                                                                               const std::string& session_id,
                                                                               boost::system::error_code& ec)
{
    using namespace boost::asio::experimental::awaitable_operators;    // NOLINT

    const auto executor = co_await boost::asio::this_coro::executor;
    const auto deadline = std::chrono::steady_clock::now() + kUpstreamHandshakeTimeout;
    boost::asio::steady_timer timer(executor);
    timer.expires_at(deadline);
    boost::system::error_code timer_ec;

    auto tcp_outcome =
        co_await (net::tcp_byte_stream::connect(
                      executor,
                      configuration.reality_server_host,
                      std::to_string(configuration.reality_server_port),
                      configuration.outbound_mark,
                      session_id,
                      ec) ||
                  timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, timer_ec)));
    if (tcp_outcome.index() == 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::timed_out);
        co_return std::nullopt;
    }

    auto tcp_stream = std::get<0>(std::move(tcp_outcome));
    if (ec)
    {
        co_return std::nullopt;
    }

    reality::client_config reality_configuration;
    reality_configuration.server_name = configuration.reality_server_name;
    reality_configuration.server_public_key = configuration.reality_server_public_key;
    reality_configuration.short_id = configuration.reality_short_id;

    timer.expires_at(deadline);
    timer_ec.clear();
    auto reality_outcome = co_await (reality::reality_stream::connect(std::move(*tcp_stream), std::move(reality_configuration), session_id, ec) ||
                                     timer.async_wait(boost::asio::redirect_error(boost::asio::use_awaitable, timer_ec)));
    if (reality_outcome.index() == 1)
    {
        ec = boost::system::errc::make_error_code(boost::system::errc::timed_out);
        co_return std::nullopt;
    }
    co_return std::get<0>(std::move(reality_outcome));
}

boost::asio::awaitable<std::optional<vision::vision_stream>> connect_vision(reality::reality_stream reality,
                                                                            const app::config& configuration,
                                                                            const target& destination,
                                                                            const std::string& session_id,
                                                                            boost::system::error_code& ec)
{
    vless::client_config vless_configuration;
    vless_configuration.user_id = configuration.vless_user_id;
    vless_configuration.destination = destination.destination;
    vless_configuration.destination_port = destination.port;
    auto vless_stream = co_await vless::vless_stream::connect(std::move(reality), std::move(vless_configuration), session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    co_return co_await vision::vision_stream::connect(std::move(*vless_stream), configuration.vless_user_id, session_id, ec);
}

boost::asio::awaitable<std::optional<vless::vless_udp_stream>> connect_udp(const app::config& configuration,
                                                                           const target& destination,
                                                                           const std::string& session_id,
                                                                           boost::system::error_code& ec)
{
    auto reality_stream = co_await connect_reality(configuration, session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    vless::client_config vless_configuration;
    vless_configuration.user_id = configuration.vless_user_id;
    vless_configuration.destination = destination.destination;
    vless_configuration.destination_port = destination.port;
    co_return co_await vless::vless_udp_stream::connect(
        std::move(*reality_stream), std::move(vless_configuration), session_id, ec);
}

}    // namespace rv::proxy

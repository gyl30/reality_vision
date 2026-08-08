#include "proxy_common.hpp"

#include "config.hpp"
#include "reality_config.hpp"
#include "tcp_byte_stream.hpp"

#include <boost/asio/this_coro.hpp>

#include <string>
#include <utility>

namespace rv::proxy
{

boost::asio::awaitable<std::optional<reality::reality_stream>> connect_reality(const app::config& configuration,
                                                                               const std::string& session_id,
                                                                               boost::system::error_code& ec)
{
    const auto executor = co_await boost::asio::this_coro::executor;
    auto tcp_stream = co_await net::tcp_byte_stream::connect(
        executor, configuration.reality_server_host, std::to_string(configuration.reality_server_port), session_id, ec);
    if (ec)
    {
        co_return std::nullopt;
    }

    reality::client_config reality_configuration;
    reality_configuration.server_name = configuration.reality_server_name;
    reality_configuration.server_public_key = configuration.reality_server_public_key;
    reality_configuration.short_id = configuration.reality_short_id;
    co_return co_await reality::reality_stream::connect(std::move(*tcp_stream), std::move(reality_configuration), session_id, ec);
}

}    // namespace rv::proxy

#include "config.hpp"
#include "protocol_tests.hpp"
#include "tcp_proxy.hpp"
#include "transparent.hpp"
#include "udp_proxy.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <exception>
#include <optional>
#include <string>
#include <utility>

namespace
{

using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;

tcp::acceptor create_acceptor(boost::asio::any_io_executor executor,
                              const tcp::endpoint& endpoint,
                              const bool enable_transparent,
                              boost::system::error_code& ec)
{
    tcp::acceptor acceptor(executor);
    acceptor.open(tcp::v4(), ec);
    if (ec)
    {
        return acceptor;
    }

    acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return acceptor;
    }

    if (enable_transparent)
    {
        ec = rv::transparent::enable_ipv4_transparent(acceptor);
        if (ec)
        {
            return acceptor;
        }
    }

    acceptor.bind(endpoint, ec);
    if (ec)
    {
        return acceptor;
    }

    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    return acceptor;
}

void log_server_exception(const std::string& server_name, const std::exception_ptr& exception)
{
    if (!exception)
    {
        return;
    }

    try
    {
        std::rethrow_exception(exception);
    }
    catch (const std::exception& error)
    {
        spdlog::error("{} server unexpected exception: {}", server_name, error.what());
    }
    catch (...)
    {
        spdlog::error("{} server unexpected non-standard exception", server_name);
    }
}

}    // namespace

int main(int argc, char* argv[])
{
    spdlog::set_pattern("%Y-%m-%d %H:%M:%S.%e %^%l%$ %v");

    try
    {
        const auto configuration = rv::app::parse_config(argc, argv);
        if (!configuration)
        {
            return static_cast<int>(configuration.error());
        }
        if (configuration->self_test)
        {
            return rv::testing::run_protocol_tests();
        }

        boost::asio::io_context context(1);
        boost::system::error_code ec;
        std::optional<tcp::acceptor> socks_acceptor;
        std::optional<tcp::acceptor> redirect_acceptor;
        std::optional<tcp::acceptor> tproxy_acceptor;
        std::optional<udp::socket> tproxy_udp_socket;

        if (configuration->socks_listen_port != 0)
        {
            socks_acceptor.emplace(create_acceptor(
                context.get_executor(), tcp::endpoint(boost::asio::ip::address_v4::loopback(), configuration->socks_listen_port), false, ec));
            if (ec)
            {
                spdlog::error("failed to create socks5 listener: {}", ec.message());
                return 1;
            }
        }
        if (configuration->redirect_listen_port != 0)
        {
            redirect_acceptor.emplace(create_acceptor(
                context.get_executor(), tcp::endpoint(tcp::v4(), configuration->redirect_listen_port), false, ec));
            if (ec)
            {
                spdlog::error("failed to create redirect listener: {}", ec.message());
                return 1;
            }
        }
        if (configuration->tproxy_listen_port != 0)
        {
            tproxy_acceptor.emplace(
                create_acceptor(context.get_executor(), tcp::endpoint(tcp::v4(), configuration->tproxy_listen_port), true, ec));
            if (ec)
            {
                spdlog::error("failed to create tproxy listener: {}", ec.message());
                return 1;
            }

            tproxy_udp_socket.emplace(rv::udp_proxy::create_tproxy_socket(context.get_executor(), configuration->tproxy_listen_port, ec));
            if (ec)
            {
                spdlog::error("failed to create tproxy udp listener: {}", ec.message());
                return 1;
            }
        }

        boost::system::error_code socks_server_ec;
        boost::system::error_code redirect_server_ec;
        boost::system::error_code tproxy_server_ec;
        boost::system::error_code tproxy_udp_server_ec;
        bool server_failed = false;

        const auto spawn_server = [&](auto server, const std::string& server_name, boost::system::error_code& server_ec)
        {
            auto* const server_error = &server_ec;
            boost::asio::co_spawn(
                context,
                std::move(server),
                [&context, server_error, &server_failed, server_name](const std::exception_ptr& exception)
                {
                    server_failed = true;
                    if (exception)
                    {
                        log_server_exception(server_name, exception);
                    }
                    else if (*server_error)
                    {
                        spdlog::error("{} server failed: {}", server_name, server_error->message());
                    }
                    else
                    {
                        spdlog::error("{} server stopped unexpectedly", server_name);
                    }
                    context.stop();
                });
        };

        if (socks_acceptor)
        {
            spawn_server(rv::tcp_proxy::run_socks_server(std::move(*socks_acceptor), *configuration, socks_server_ec), "socks5", socks_server_ec);
        }
        if (redirect_acceptor)
        {
            spawn_server(rv::tcp_proxy::run_redirect_server(std::move(*redirect_acceptor), *configuration, redirect_server_ec),
                         "redirect",
                         redirect_server_ec);
        }
        if (tproxy_acceptor)
        {
            spawn_server(rv::tcp_proxy::run_tproxy_server(std::move(*tproxy_acceptor), *configuration, tproxy_server_ec),
                         "tproxy",
                         tproxy_server_ec);
        }
        if (tproxy_udp_socket)
        {
            spawn_server(rv::udp_proxy::run_tproxy_server(std::move(*tproxy_udp_socket), *configuration, tproxy_udp_server_ec),
                         "tproxy udp",
                         tproxy_udp_server_ec);
        }

        context.run();
        return server_failed ? 1 : 0;
    }
    catch (const std::exception& error)
    {
        spdlog::error("unexpected fatal exception: {}", error.what());
        return 1;
    }
}

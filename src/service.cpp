#include "service.hpp"

#include "runtime_state.hpp"
#include "tcp_proxy.hpp"
#include "transparent.hpp"
#include "udp_proxy.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <atomic>
#include <cerrno>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <sys/socket.h>

namespace rv::app
{

using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;

static tcp::acceptor create_acceptor(boost::asio::io_context& executor,
                                     const tcp::endpoint& endpoint,
                                     const bool enable_transparent,
                                     const bool enable_reuse_port,
                                     boost::system::error_code& ec)
{
    tcp::acceptor acceptor(executor);
    acceptor.open(tcp::v4(), ec);
    if (ec)
    {
        return acceptor;
    }

    const int reuse_port = 1;
    if (enable_reuse_port && ::setsockopt(acceptor.native_handle(), SOL_SOCKET, SO_REUSEPORT, &reuse_port, sizeof(reuse_port)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::generic_category());
        return acceptor;
    }

    acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec)
    {
        return acceptor;
    }

    if (enable_transparent)
    {
        ec = transparent::enable_ipv4_transparent(acceptor);
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

service::service(config configuration) : configuration_(std::move(configuration)) {}

void service::run()
{
    auto runtime = std::make_shared<runtime_state>();
    for (std::size_t i = 0; i < configuration_.worker_count; ++i)
    {
        contexts_.push_back(std::make_shared<boost::asio::io_context>(1));
    }

    for (std::size_t worker_index = 0; worker_index < contexts_.size(); ++worker_index)
    {
        auto& context = contexts_[worker_index];
        const bool reuse_port = configuration_.worker_count > 1;
        boost::system::error_code ec;
        std::optional<tcp::acceptor> socks_acceptor;
        std::optional<tcp::acceptor> redirect_acceptor;
        std::optional<tcp::acceptor> tproxy_acceptor;
        std::optional<udp::socket> tproxy_udp_socket;

        if (configuration_.socks_listen_port != 0)
        {
            socks_acceptor.emplace(create_acceptor(
                *context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), configuration_.socks_listen_port), false, reuse_port, ec));
            if (ec)
            {
                spdlog::error("failed to create socks5 listener: {}", ec.message());
                return;
            }
        }
        if (configuration_.redirect_listen_port != 0)
        {
            redirect_acceptor.emplace(
                create_acceptor(*context, tcp::endpoint(tcp::v4(), configuration_.redirect_listen_port), false, reuse_port, ec));
            if (ec)
            {
                spdlog::error("failed to create redirect listener: {}", ec.message());
                return;
            }
        }
        if (configuration_.tproxy_listen_port != 0)
        {
            tproxy_acceptor.emplace(create_acceptor(*context, tcp::endpoint(tcp::v4(), configuration_.tproxy_listen_port), true, reuse_port, ec));
            if (ec)
            {
                spdlog::error("failed to create tproxy listener: {}", ec.message());
                return;
            }

            tproxy_udp_socket.emplace(udp_proxy::create_tproxy_socket(context->get_executor(), configuration_.tproxy_listen_port, reuse_port, ec));
            if (ec)
            {
                spdlog::error("failed to create tproxy udp listener: {}", ec.message());
                return;
            }
        }

        if (socks_acceptor)
        {
            spawn_server(*context, tcp_proxy::run_socks_server(std::move(*socks_acceptor), configuration_, runtime, worker_index), "socks5");
        }
        if (redirect_acceptor)
        {
            spawn_server(*context, tcp_proxy::run_redirect_server(std::move(*redirect_acceptor), configuration_, runtime, worker_index), "redirect");
        }
        if (tproxy_acceptor)
        {
            spawn_server(*context, tcp_proxy::run_tproxy_server(std::move(*tproxy_acceptor), configuration_, runtime, worker_index), "tproxy");
        }
        if (tproxy_udp_socket)
        {
            spawn_server(*context, udp_proxy::run_tproxy_server(std::move(*tproxy_udp_socket), configuration_, runtime, worker_index), "tproxy udp");
        }
    }

    workers_.reserve(contexts_.size());
    for (const auto& context : contexts_)
    {
        workers_.emplace_back([context] { context->run(); });
    }
    for (auto& worker : workers_)
    {
        worker.join();
    }
}
void service::spawn_server(boost::asio::io_context& context, boost::asio::awaitable<void> server, const std::string& server_name)
{
    boost::asio::co_spawn(
        context, std::move(server), [server_name, this](const std::exception_ptr& exception) { server_exception(server_name, exception); });
}
void service::server_exception(const std::string& server_name, const std::exception_ptr& exception)
{
    for (const auto& context : contexts_)
    {
        context->stop();
    }

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
        spdlog::error("{} server unexpected exception {}", server_name, error.what());
    }
    catch (...)
    {
        spdlog::error("{} server unexpected non standard exception", server_name);
    }
}

}    // namespace rv::app

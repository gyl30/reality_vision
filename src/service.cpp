#include <cerrno>
#include <utility>
#include <sys/socket.h>

#include <spdlog/spdlog.h>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/system/error_code.hpp>

#include "service.hpp"
#include "tcp_proxy.hpp"
#include "udp_proxy.hpp"
#include "transparent.hpp"
#include "proxy_service.hpp"

namespace rv::app
{
namespace
{

using tcp = boost::asio::ip::tcp;

tcp::acceptor create_acceptor(boost::asio::io_context& context,
                              const tcp::endpoint& endpoint,
                              const bool enable_transparent,
                              const bool enable_reuse_port,
                              boost::system::error_code& ec)
{
    tcp::acceptor acceptor(context);
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

}    // namespace

service::service(config configuration) : configuration_(std::move(configuration)) {}

void service::startup()
{
    contexts_.reserve(configuration_.worker_count);
    for (std::size_t i = 0; i < configuration_.worker_count; ++i)
    {
        contexts_.push_back(std::make_shared<boost::asio::io_context>(1));
    }

    const bool reuse_port = configuration_.worker_count > 1;
    for (std::size_t worker_index = 0; worker_index < contexts_.size(); ++worker_index)
    {
        const auto& context = contexts_[worker_index];
        const auto worker_id = std::to_string(worker_index);
        boost::system::error_code ec;

        if (configuration_.socks_listen_port != 0)
        {
            const auto service_id = "socks_" + worker_id;
            auto acceptor = create_acceptor(
                *context, tcp::endpoint(boost::asio::ip::address_v4::loopback(), configuration_.socks_listen_port), false, reuse_port, ec);
            if (ec)
            {
                spdlog::error("{} listener creation failed: {}", service_id, ec.message());
                return;
            }
            proxy_services_.push_back(std::make_shared<tcp_proxy::socks_proxy>(std::move(acceptor), configuration_, service_id));
        }

        if (configuration_.redirect_listen_port != 0)
        {
            const auto service_id = "redirect_" + worker_id;
            auto acceptor = create_acceptor(*context, tcp::endpoint(tcp::v4(), configuration_.redirect_listen_port), false, reuse_port, ec);
            if (ec)
            {
                spdlog::error("{} listener creation failed: {}", service_id, ec.message());
                return;
            }
            proxy_services_.push_back(std::make_shared<tcp_proxy::redirect_proxy>(std::move(acceptor), configuration_, service_id));
        }

        if (configuration_.tproxy_listen_port != 0)
        {
            const auto tcp_service_id = "tcp_tproxy_" + worker_id;
            auto acceptor = create_acceptor(*context, tcp::endpoint(tcp::v4(), configuration_.tproxy_listen_port), true, reuse_port, ec);
            if (ec)
            {
                spdlog::error("{} listener creation failed: {}", tcp_service_id, ec.message());
                return;
            }
            proxy_services_.push_back(std::make_shared<tcp_proxy::tcp_tproxy>(std::move(acceptor), configuration_, tcp_service_id));

            const auto udp_service_id = "udp_tproxy_" + worker_id;
            auto socket = udp_proxy::create_tproxy_socket(context->get_executor(), configuration_.tproxy_listen_port, reuse_port, ec);
            if (ec)
            {
                spdlog::error("{} listener creation failed: {}", udp_service_id, ec.message());
                return;
            }
            proxy_services_.push_back(std::make_shared<udp_proxy::udp_tproxy>(std::move(socket), configuration_, udp_service_id));
        }
    }
    for (const auto& proxy_service : proxy_services_)
    {
        proxy_service->startup();
    }
    workers_.reserve(contexts_.size());
    for (const auto& context : contexts_)
    {
        workers_.emplace_back(
            [this, context]
            {
                context->run();
                shutdown();
            });
    }
    for (auto& worker : workers_)
    {
        worker.join();
    }
}

void service::shutdown()
{
    if (stopping_.exchange(true, std::memory_order_relaxed))
    {
        return;
    }
    for (const auto& context : contexts_)
    {
        context->stop();
    }
}

}    // namespace rv::app

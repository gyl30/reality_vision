#include "config.hpp"
#include "protocol_tests.hpp"
#include "runtime_state.hpp"
#include "tcp_proxy.hpp"
#include "transparent.hpp"
#include "udp_proxy.hpp"

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <spdlog/spdlog.h>

#include <exception>
#include <atomic>
#include <cerrno>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include <sys/socket.h>

namespace
{

using tcp = boost::asio::ip::tcp;
using udp = boost::asio::ip::udp;

tcp::acceptor create_acceptor(boost::asio::any_io_executor executor,
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

        auto runtime = std::make_shared<rv::app::runtime_state>();
        using context_ptr = std::shared_ptr<boost::asio::io_context>;
        auto contexts = std::make_shared<std::vector<context_ptr>>();
        contexts->reserve(configuration->worker_count);
        for (std::size_t i = 0; i < configuration->worker_count; ++i)
        {
            contexts->push_back(std::make_shared<boost::asio::io_context>(1));
        }

        std::atomic_bool server_failed{false};
        const auto stop_all = [contexts]
        {
            for (const auto& context : *contexts)
            {
                context->stop();
            }
        };
        const auto spawn_server = [&](const context_ptr& context,
                                      auto server,
                                      const std::string& server_name,
                                      const std::shared_ptr<boost::system::error_code>& server_ec)
        {
            boost::asio::co_spawn(*context,
                                  std::move(server),
                                  [context, server_ec, server_name, &server_failed, stop_all](const std::exception_ptr& exception)
                                  {
                                      server_failed.store(true, std::memory_order_relaxed);
                                      if (exception)
                                      {
                                          log_server_exception(server_name, exception);
                                      }
                                      else if (*server_ec)
                                      {
                                          spdlog::error("{} server failed: {}", server_name, server_ec->message());
                                      }
                                      else
                                      {
                                          spdlog::error("{} server stopped unexpectedly", server_name);
                                      }
                                      stop_all();
                                  });
        };

        for (std::size_t worker_index = 0; worker_index < contexts->size(); ++worker_index)
        {
            const auto& context = (*contexts)[worker_index];
            const bool reuse_port = configuration->worker_count > 1;
            boost::system::error_code ec;
            std::optional<tcp::acceptor> socks_acceptor;
            std::optional<tcp::acceptor> redirect_acceptor;
            std::optional<tcp::acceptor> tproxy_acceptor;
            std::optional<udp::socket> tproxy_udp_socket;

            if (configuration->socks_listen_port != 0)
            {
                socks_acceptor.emplace(create_acceptor(context->get_executor(),
                                                        tcp::endpoint(boost::asio::ip::address_v4::loopback(), configuration->socks_listen_port),
                                                        false,
                                                        reuse_port,
                                                        ec));
                if (ec)
                {
                    spdlog::error("failed to create socks5 listener: {}", ec.message());
                    return 1;
                }
            }
            if (configuration->redirect_listen_port != 0)
            {
                redirect_acceptor.emplace(create_acceptor(
                    context->get_executor(), tcp::endpoint(tcp::v4(), configuration->redirect_listen_port), false, reuse_port, ec));
                if (ec)
                {
                    spdlog::error("failed to create redirect listener: {}", ec.message());
                    return 1;
                }
            }
            if (configuration->tproxy_listen_port != 0)
            {
                tproxy_acceptor.emplace(create_acceptor(
                    context->get_executor(), tcp::endpoint(tcp::v4(), configuration->tproxy_listen_port), true, reuse_port, ec));
                if (ec)
                {
                    spdlog::error("failed to create tproxy listener: {}", ec.message());
                    return 1;
                }

                tproxy_udp_socket.emplace(
                    rv::udp_proxy::create_tproxy_socket(context->get_executor(), configuration->tproxy_listen_port, reuse_port, ec));
                if (ec)
                {
                    spdlog::error("failed to create tproxy udp listener: {}", ec.message());
                    return 1;
                }
            }

            if (socks_acceptor)
            {
                const auto server_ec = std::make_shared<boost::system::error_code>();
                spawn_server(context,
                             rv::tcp_proxy::run_socks_server(
                                 std::move(*socks_acceptor), *configuration, runtime, worker_index, *server_ec),
                             "socks5",
                             server_ec);
            }
            if (redirect_acceptor)
            {
                const auto server_ec = std::make_shared<boost::system::error_code>();
                spawn_server(context,
                             rv::tcp_proxy::run_redirect_server(
                                 std::move(*redirect_acceptor), *configuration, runtime, worker_index, *server_ec),
                             "redirect",
                             server_ec);
            }
            if (tproxy_acceptor)
            {
                const auto server_ec = std::make_shared<boost::system::error_code>();
                spawn_server(context,
                             rv::tcp_proxy::run_tproxy_server(
                                 std::move(*tproxy_acceptor), *configuration, runtime, worker_index, *server_ec),
                             "tproxy",
                             server_ec);
            }
            if (tproxy_udp_socket)
            {
                const auto server_ec = std::make_shared<boost::system::error_code>();
                spawn_server(context,
                             rv::udp_proxy::run_tproxy_server(
                                 std::move(*tproxy_udp_socket), *configuration, runtime, worker_index, *server_ec),
                             "tproxy udp",
                             server_ec);
            }
        }

        std::vector<std::thread> workers;
        workers.reserve(contexts->size());
        for (const auto& context : *contexts)
        {
            workers.emplace_back([context] { context->run(); });
        }
        for (auto& worker : workers)
        {
            worker.join();
        }
        return server_failed.load(std::memory_order_relaxed) ? 1 : 0;
    }
    catch (const std::exception& error)
    {
        spdlog::error("unexpected fatal exception: {}", error.what());
        return 1;
    }
}

#include <cerrno>
#include <cstdint>
#include <utility>
#include <sys/socket.h>

#include <spdlog/spdlog.h>
#include <boost/asio/write.hpp>
#include <boost/system/errc.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/redirect_error.hpp>

#include "tcp_byte_stream.hpp"

namespace rv::net
{
namespace
{

void set_socket_mark(boost::asio::ip::tcp::socket& socket, const std::uint32_t mark, boost::system::error_code& ec)
{
#ifdef SO_MARK
    if (::setsockopt(socket.native_handle(), SOL_SOCKET, SO_MARK, &mark, sizeof(mark)) != 0)
    {
        ec = boost::system::error_code(errno, boost::system::generic_category());
    }
#else
    static_cast<void>(socket);
    static_cast<void>(mark);
    ec = boost::system::errc::make_error_code(boost::system::errc::operation_not_supported);
#endif
}

}    // namespace

tcp_byte_stream::tcp_byte_stream(boost::asio::ip::tcp::socket socket, std::string session_id)
    : session_id_(std::move(session_id)), socket_(std::move(socket))
{
}

boost::asio::awaitable<std::optional<tcp_byte_stream>> tcp_byte_stream::connect(
    boost::asio::any_io_executor executor,
    const std::span<const boost::asio::ip::tcp::endpoint> endpoints,
    const std::uint32_t mark,
    std::string session_id,
    boost::system::error_code& ec)
{
    // 逐个尝试地址；mark 必须在 connect 之前设置，路由决策发生在 connect 时。
    boost::asio::ip::tcp::socket socket(executor);
    for (const auto& endpoint : endpoints)
    {
        boost::system::error_code ignored;
        socket.close(ignored);
        ec.clear();
        socket.open(endpoint.protocol(), ec);
        if (!ec && mark != 0)
        {
            set_socket_mark(socket, mark, ec);
        }
        if (ec)
        {
            co_return std::nullopt;
        }

        co_await socket.async_connect(endpoint, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
        if (!ec)
        {
            spdlog::info("{} tcp connected to {}:{}", session_id, endpoint.address().to_string(), endpoint.port());
            co_return tcp_byte_stream(std::move(socket), std::move(session_id));
        }
    }
    if (!ec)
    {
        ec = boost::asio::error::host_not_found;
    }
    co_return std::nullopt;
}

boost::asio::awaitable<std::size_t> tcp_byte_stream::read(std::span<std::uint8_t> output, boost::system::error_code& ec)
{
    if (output.empty())
    {
        co_return 0;
    }
    co_return co_await socket_.async_read_some(boost::asio::buffer(output.data(), output.size()),
                                               boost::asio::redirect_error(boost::asio::use_awaitable, ec));
}

boost::asio::awaitable<void> tcp_byte_stream::write(std::span<const std::uint8_t> input, boost::system::error_code& ec)
{
    if (input.empty())
    {
        co_return;
    }
    co_await boost::asio::async_write(
        socket_, boost::asio::buffer(input.data(), input.size()), boost::asio::redirect_error(boost::asio::use_awaitable, ec));
}

void tcp_byte_stream::shutdown_send(boost::system::error_code& ec) noexcept
{
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
    if (ec == boost::asio::error::not_connected)
    {
        ec = {};
    }
}

void tcp_byte_stream::shutdown() noexcept
{
    boost::system::error_code ignored;
    socket_.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
}

}    // namespace rv::net

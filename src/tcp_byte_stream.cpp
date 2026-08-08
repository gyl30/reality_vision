#include "tcp_byte_stream.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/redirect_error.hpp>
#include <boost/asio/use_awaitable.hpp>
#include <boost/asio/write.hpp>
#include <spdlog/spdlog.h>

#include <utility>

namespace rv::net
{

tcp_byte_stream::tcp_byte_stream(boost::asio::ip::tcp::socket socket, std::string session_id)
    : session_id_(std::move(session_id)), socket_(std::move(socket))
{
}

boost::asio::awaitable<std::optional<tcp_byte_stream>> tcp_byte_stream::connect(
    boost::asio::any_io_executor executor, std::string host, std::string service, std::string session_id, boost::system::error_code& ec)
{
    boost::asio::ip::tcp::resolver resolver(executor);
    const auto endpoints = co_await resolver.async_resolve(host, service, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        co_return std::nullopt;
    }

    boost::asio::ip::tcp::socket socket(executor);
    const auto endpoint = co_await boost::asio::async_connect(socket, endpoints, boost::asio::redirect_error(boost::asio::use_awaitable, ec));
    if (ec)
    {
        co_return std::nullopt;
    }

    spdlog::info("{} tcp connected to {}:{}", session_id, endpoint.address().to_string(), endpoint.port());
    co_return tcp_byte_stream(std::move(socket), std::move(session_id));
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

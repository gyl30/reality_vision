#ifndef REALITY_VISION_TCP_BYTE_STREAM_HPP
#define REALITY_VISION_TCP_BYTE_STREAM_HPP

#include <boost/asio/any_io_executor.hpp>
#include <boost/asio/awaitable.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace rv::net
{

class tcp_byte_stream
{
   public:
    explicit tcp_byte_stream(boost::asio::ip::tcp::socket socket, std::string session_id);

    [[nodiscard]] static boost::asio::awaitable<std::optional<tcp_byte_stream>> connect(
        boost::asio::any_io_executor executor, std::string host, std::string service, std::string session_id, boost::system::error_code& ec);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> write(std::span<const std::uint8_t> input, boost::system::error_code& ec);

    void shutdown_send(boost::system::error_code& ec) noexcept;
    void shutdown() noexcept;

   private:
    std::string session_id_;
    boost::asio::ip::tcp::socket socket_;
};

}    // namespace rv::net

#endif    // REALITY_VISION_TCP_BYTE_STREAM_HPP

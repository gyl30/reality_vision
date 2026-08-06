#ifndef REALITY_VISION_REALITY_STREAM_HPP
#define REALITY_VISION_REALITY_STREAM_HPP

#include "byte_queue.hpp"
#include "reality_config.hpp"
#include "reality_record.hpp"
#include "tcp_byte_stream.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace rv::reality
{

enum class receive_mode { tls, raw, closed };
enum class send_mode { tls, draining, raw, closed };

class reality_stream
{
public:
    [[nodiscard]] static boost::asio::awaitable<std::optional<reality_stream>> connect(
        net::tcp_byte_stream lower,
        client_config config,
        std::string log,
        boost::system::error_code& ec);

    reality_stream(const reality_stream&) = delete;
    reality_stream& operator=(const reality_stream&) = delete;
    reality_stream(reality_stream&&) noexcept = default;
    reality_stream& operator=(reality_stream&&) noexcept = default;

    [[nodiscard]] boost::asio::awaitable<std::size_t> async_read_some(
        std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_write_all(
        std::span<const std::uint8_t> input, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_shutdown_send(boost::system::error_code& ec);

    [[nodiscard]] bool switch_receive_to_raw(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_write_final_tls_and_switch(
        std::span<const std::uint8_t> final_plaintext, boost::system::error_code& ec);

    void shutdown() noexcept;

private:
    reality_stream(
        net::tcp_byte_stream lower,
        record_key read_key,
        record_key write_key,
        std::string log);

    [[nodiscard]] boost::asio::awaitable<void> write_tls(
        std::span<const std::uint8_t> input, boost::system::error_code& ec);
    [[nodiscard]] bool process_post_handshake(boost::system::error_code& ec);

    net::tcp_byte_stream lower_;
    record_key read_key_;
    record_key write_key_;
    core::byte_queue plaintext_{max_tls_plaintext + 1};
    core::byte_queue post_handshake_{1U << 20};
    receive_mode receive_mode_{receive_mode::tls};
    send_mode send_mode_{send_mode::tls};
    std::size_t useless_records_{0};
    bool read_in_progress_{false};
    bool write_in_progress_{false};
    std::string log_;
};

} // namespace rv::reality

#endif

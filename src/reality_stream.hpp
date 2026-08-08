#ifndef REALITY_VISION_REALITY_STREAM_HPP
#define REALITY_VISION_REALITY_STREAM_HPP

#include "byte_queue.hpp"
#include "reality_config.hpp"
#include "reality_record.hpp"
#include "tcp_byte_stream.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rv::reality
{

enum class receive_mode : std::uint8_t
{
    kTls,
    kRaw,
    kClosed
};

enum class send_mode : std::uint8_t
{
    kTls,
    kSwitchingToRaw,
    kRaw,
    kClosed
};

class reality_stream
{
   public:
    [[nodiscard]] static boost::asio::awaitable<std::optional<reality_stream>> connect(net::tcp_byte_stream tcp,
                                                                                       client_config configuration,
                                                                                       std::string session_id,
                                                                                       boost::system::error_code& ec);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> write(std::span<const std::uint8_t> input, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec);

    void switch_receive_to_raw(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> write_final_tls_and_switch_to_raw(std::span<const std::uint8_t> final_plaintext,
                                                                                 boost::system::error_code& ec);

    void shutdown() noexcept;

   private:
    struct encrypted_record
    {
        std::array<std::uint8_t, tls::kRecordHeaderSize> header{};
        std::vector<std::uint8_t> payload;
    };

    reality_stream(net::tcp_byte_stream tcp, record_key receive_key, record_key send_key, std::string session_id);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read_raw(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::size_t> read_tls(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::optional<encrypted_record>> read_tls_record(boost::system::error_code& ec);
    [[nodiscard]] std::optional<std::size_t> process_decrypted_record(const opened_record& plaintext,
                                                                      std::span<std::uint8_t> output,
                                                                      boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> write_tls_records(std::span<const std::uint8_t> input, boost::system::error_code& ec);
    void process_post_handshake_messages(boost::system::error_code& ec);

    net::tcp_byte_stream tcp_;
    record_key receive_key_;
    record_key send_key_;
    core::byte_queue plaintext_buffer_{tls::kMaximumPlaintextSize};
    core::byte_queue post_handshake_buffer_{tls::kMaximumHandshakeMessageSize};
    receive_mode receive_mode_{receive_mode::kTls};
    send_mode send_mode_{send_mode::kTls};
    std::size_t ignored_tls_record_count_{0};
    std::string session_id_;
};

}    // namespace rv::reality

#endif

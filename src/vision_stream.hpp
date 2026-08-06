#ifndef REALITY_VISION_VISION_STREAM_HPP
#define REALITY_VISION_VISION_STREAM_HPP

#include "vision_codec.hpp"
#include "vless_stream.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace rv::vision
{

class vision_stream
{
   public:
    [[nodiscard]] static boost::asio::awaitable<std::optional<vision_stream>> connect(vless::vless_stream lower,
                                                                                      std::array<std::uint8_t, user_id_size> user_id,
                                                                                      std::string log,
                                                                                      boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::size_t> async_read_some(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_write_all(std::span<const std::uint8_t> input, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_shutdown_send(boost::system::error_code& ec);
    void shutdown() noexcept;

   private:
    enum class read_phase : uint8_t
    {
        header,
        content,
        padding,
        through
    };

    vision_stream(vless::vless_stream lower, std::array<std::uint8_t, user_id_size> user_id, std::string log);

    [[nodiscard]] boost::asio::awaitable<bool> read_frame_header(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> discard_padding(boost::system::error_code& ec);

    vless::vless_stream lower_;
    std::array<std::uint8_t, user_id_size> user_id_{};
    read_phase read_phase_{read_phase::header};
    bool read_needs_user_id_{true};
    command read_command_{command::continue_padding};
    std::size_t remaining_content_{0};
    std::size_t remaining_padding_{0};
    bool write_padding_{true};
    bool write_sent_user_id_{false};
    bool write_seen_tls_{false};
    bool direct_enabled_{false};
    server_hello_filter server_hello_filter_;
    std::string log_;
};

}    // namespace rv::vision

#endif

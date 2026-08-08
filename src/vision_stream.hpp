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
    [[nodiscard]] static boost::asio::awaitable<std::optional<vision_stream>> connect(vless::vless_stream vless,
                                                                                      std::array<std::uint8_t, kUserIdSize> user_id,
                                                                                      std::string session_id,
                                                                                      boost::system::error_code& ec);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> write(std::span<const std::uint8_t> input, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec);

    void shutdown() noexcept;

   private:
    enum class receive_phase : std::uint8_t
    {
        kHeader,
        kContent,
        kPadding,
        kPassthrough
    };

    struct send_plan
    {
        command final_command{command::kContinuePadding};
        std::size_t vision_framed_size{};
        bool use_long_padding{};
    };

    vision_stream(vless::vless_stream vless, std::array<std::uint8_t, kUserIdSize> user_id, std::string session_id);

    [[nodiscard]] boost::asio::awaitable<bool> read_next_frame_header(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::size_t> read_frame_content(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> finish_received_frame(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> discard_frame_padding(boost::system::error_code& ec);

    [[nodiscard]] send_plan make_send_plan(std::span<const std::uint8_t> input) noexcept;
    [[nodiscard]] boost::asio::awaitable<void> write_vision_frames(std::span<const std::uint8_t> input,
                                                                   command final_command,
                                                                   bool use_long_padding,
                                                                   boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> end_padding_before_shutdown(boost::system::error_code& ec);

    vless::vless_stream vless_;
    std::array<std::uint8_t, kUserIdSize> user_id_{};

    receive_phase receive_phase_{receive_phase::kHeader};
    bool expect_user_id_{true};
    command received_command_{command::kContinuePadding};
    std::size_t content_remaining_{0};
    std::size_t padding_remaining_{0};

    bool send_padding_active_{true};
    bool direct_mode_allowed_{false};
    client_tls_record_tracker client_tls_record_tracker_;
    server_hello_tracker server_hello_tracker_;
    std::string session_id_;
};

}    // namespace rv::vision

#endif

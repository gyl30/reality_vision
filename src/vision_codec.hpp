#ifndef REALITY_VISION_VISION_CODEC_HPP
#define REALITY_VISION_VISION_CODEC_HPP

#include "tls_constants.hpp"

#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace rv::vision
{

inline constexpr std::size_t kUserIdSize = 16;
inline constexpr std::size_t kFullHeaderSize = 21;
inline constexpr std::size_t kShortHeaderSize = 5;
inline constexpr std::size_t kXrayBufferSize = 8192;

enum class command : std::uint8_t
{
    kContinuePadding = 0x00,
    kEndPadding = 0x01,
    kDirect = 0x02,
};

struct frame_header
{
    command frame_command{};
    std::uint16_t content_length{};
    std::uint16_t padding_length{};
};

[[nodiscard]] boost::system::error_code decode_header(std::span<const std::uint8_t> header,
                                                      bool contains_user_id,
                                                      std::span<const std::uint8_t, kUserIdSize> expected_user_id,
                                                      frame_header& output);

[[nodiscard]] std::vector<std::uint8_t> encode_frame(command frame_command,
                                                     std::optional<std::span<const std::uint8_t, kUserIdSize>> user_id,
                                                     std::span<const std::uint8_t> content,
                                                     bool long_padding,
                                                     boost::system::error_code& ec);

enum class client_stream_kind : std::uint8_t
{
    kUndecided,
    kNonTls,
    kTls
};

struct client_tls_observation
{
    client_stream_kind kind{client_stream_kind::kUndecided};
    // 当前输入中第一个完整加密 TLS record 结束位置的后一字节偏移。
    std::optional<std::size_t> encrypted_record_end_offset;
    bool tracking_failed{false};
};

class client_tls_record_tracker
{
   public:
    [[nodiscard]] client_tls_observation observe(std::span<const std::uint8_t> input) noexcept;
    [[nodiscard]] bool tls_detected() const noexcept { return kind_ == client_stream_kind::kTls; }

   private:
    enum class phase : std::uint8_t
    {
        kHeader,
        kPayload,
        kDisabled
    };

    void disable_tracking() noexcept;
    [[nodiscard]] bool parse_record_header() noexcept;
    [[nodiscard]] bool consume_record_header(std::span<const std::uint8_t> input, std::size_t& position) noexcept;
    [[nodiscard]] bool detect_client_hello(std::span<const std::uint8_t> input, std::size_t& position) noexcept;

    std::array<std::uint8_t, tls::kRecordHeaderSize> header_{};
    std::size_t header_size_{0};
    std::size_t remaining_payload_{0};
    std::uint8_t record_type_{0};
    client_stream_kind kind_{client_stream_kind::kUndecided};
    phase phase_{phase::kHeader};
    bool first_record_{true};
    bool tracking_failed_{false};
};

class server_hello_tracker
{
   public:
    void observe(std::span<const std::uint8_t> input);
    [[nodiscard]] bool direct_supported() const noexcept { return direct_supported_; }

   private:
    [[nodiscard]] bool prepare_server_hello_record();
    void evaluate_server_hello();

    std::vector<std::uint8_t> buffer_;
    std::optional<std::size_t> record_length_;
    bool done_{false};
    bool direct_supported_{false};
};

}    // namespace rv::vision

#endif

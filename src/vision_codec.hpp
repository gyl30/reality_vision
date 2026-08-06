#ifndef REALITY_VISION_VISION_CODEC_HPP
#define REALITY_VISION_VISION_CODEC_HPP

#include <boost/system/error_code.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace rv::vision
{

inline constexpr std::size_t user_id_size = 16;
inline constexpr std::size_t full_header_size = 21;
inline constexpr std::size_t short_header_size = 5;
inline constexpr std::size_t xray_buffer_size = 8192;

enum class command : std::uint8_t
{
    continue_padding = 0x00,
    end_padding = 0x01,
    direct = 0x02,
};

struct frame_header
{
    command frame_command{};
    std::uint16_t content_length{};
    std::uint16_t padding_length{};
};

[[nodiscard]] bool decode_header(
    std::span<const std::uint8_t> header,
    bool contains_user_id,
    std::span<const std::uint8_t, user_id_size> expected_user_id,
    frame_header& output,
    boost::system::error_code& ec);

[[nodiscard]] std::vector<std::uint8_t> encode_frame(
    command frame_command,
    std::optional<std::span<const std::uint8_t, user_id_size>> user_id,
    std::span<const std::uint8_t> content,
    bool long_padding,
    boost::system::error_code& ec);

[[nodiscard]] bool contains_tls_client_hello(std::span<const std::uint8_t> input) noexcept;
[[nodiscard]] bool starts_tls13_application_data(std::span<const std::uint8_t> input) noexcept;
[[nodiscard]] bool consists_of_complete_tls13_application_records(
    std::span<const std::uint8_t> input) noexcept;

class server_hello_filter
{
public:
    void observe(std::span<const std::uint8_t> input);
    [[nodiscard]] bool direct_supported() const noexcept { return direct_supported_; }

private:
    void evaluate();

    std::vector<std::uint8_t> buffer_;
    std::optional<std::size_t> record_length_;
    bool done_{false};
    bool direct_supported_{false};
};

} // namespace rv::vision

#endif

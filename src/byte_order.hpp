#ifndef REALITY_VISION_BYTE_ORDER_HPP
#define REALITY_VISION_BYTE_ORDER_HPP

#include <cstdint>

namespace rv::core
{

[[nodiscard]] inline std::uint16_t read_be16(const std::uint8_t* data) noexcept
{
    return static_cast<std::uint16_t>(static_cast<std::uint16_t>(data[0]) << 8U | static_cast<std::uint16_t>(data[1]));
}

[[nodiscard]] inline std::uint32_t read_be24(const std::uint8_t* data) noexcept
{
    return static_cast<std::uint32_t>(data[0]) << 16U | static_cast<std::uint32_t>(data[1]) << 8U | static_cast<std::uint32_t>(data[2]);
}

[[nodiscard]] inline std::uint32_t read_be32(const std::uint8_t* data) noexcept
{
    return static_cast<std::uint32_t>(data[0]) << 24U | static_cast<std::uint32_t>(data[1]) << 16U |
           static_cast<std::uint32_t>(data[2]) << 8U | static_cast<std::uint32_t>(data[3]);
}

inline void write_be16(std::uint8_t* data, const std::uint16_t value) noexcept
{
    data[0] = static_cast<std::uint8_t>(value >> 8U);
    data[1] = static_cast<std::uint8_t>(value);
}

inline void write_be24(std::uint8_t* data, const std::uint32_t value) noexcept
{
    data[0] = static_cast<std::uint8_t>(value >> 16U);
    data[1] = static_cast<std::uint8_t>(value >> 8U);
    data[2] = static_cast<std::uint8_t>(value);
}

inline void write_be32(std::uint8_t* data, const std::uint32_t value) noexcept
{
    data[0] = static_cast<std::uint8_t>(value >> 24U);
    data[1] = static_cast<std::uint8_t>(value >> 16U);
    data[2] = static_cast<std::uint8_t>(value >> 8U);
    data[3] = static_cast<std::uint8_t>(value);
}

}    // namespace rv::core

#endif    // REALITY_VISION_BYTE_ORDER_HPP

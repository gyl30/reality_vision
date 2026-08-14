#ifndef REALITY_VISION_BYTE_WRITER_HPP
#define REALITY_VISION_BYTE_WRITER_HPP

#include <vector>
#include <cstdint>

namespace rv::core
{

inline void append_be16(std::vector<std::uint8_t>& output, const std::uint16_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

inline void append_be24(std::vector<std::uint8_t>& output, const std::uint32_t value)
{
    output.push_back(static_cast<std::uint8_t>(value >> 16U));
    output.push_back(static_cast<std::uint8_t>(value >> 8U));
    output.push_back(static_cast<std::uint8_t>(value));
}

}    // namespace rv::core

#endif    // REALITY_VISION_BYTE_WRITER_HPP

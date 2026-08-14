#ifndef REALITY_VISION_RV_CORE_HEX_HPP
#define REALITY_VISION_RV_CORE_HEX_HPP

#include <vector>
#include <cstdint>
#include <string_view>

namespace rv::core
{

[[nodiscard]] std::vector<std::uint8_t> decode_hex(std::string_view input);

}    // namespace rv::core

#endif    // REALITY_VISION_RV_CORE_HEX_HPP

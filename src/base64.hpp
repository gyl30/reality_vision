#ifndef REALITY_VISION_RV_CORE_BASE64_HPP
#define REALITY_VISION_RV_CORE_BASE64_HPP

#include <cstdint>
#include <string_view>
#include <vector>

namespace rv::core
{

[[nodiscard]] std::vector<std::uint8_t> decode_base64_url(std::string_view input);

}    // namespace rv::core

#endif    // REALITY_VISION_RV_CORE_BASE64_HPP

#ifndef REALITY_VISION_RV_CORE_HEX_HPP
#define REALITY_VISION_RV_CORE_HEX_HPP

#include <cstdint>
#include <string>
#include <vector>

namespace rv::core
{

class hex
{
   public:
    hex() = default;
    ~hex() = default;

   public:
    [[nodiscard]] static std::string encode_to_string(const std::uint8_t* data, std::uint32_t data_len);
    [[nodiscard]] static std::string encode_to_string(const char* data, std::uint32_t data_len);
    [[nodiscard]] static std::vector<std::uint8_t> encode_to_bytes(const std::uint8_t* data, std::uint32_t data_len);

    [[nodiscard]] static std::string decode_to_string(const std::uint8_t* data, std::uint32_t data_len);
    [[nodiscard]] static std::vector<std::uint8_t> decode_to_bytes(const std::uint8_t* data, std::uint32_t data_len);
    [[nodiscard]] static std::string decode_to_string(const char* data, std::uint32_t data_len);
    [[nodiscard]] static std::vector<std::uint8_t> decode_to_bytes(const char* data, std::uint32_t data_len);
};

}    // namespace rv::core

#endif    // REALITY_VISION_RV_CORE_HEX_HPP

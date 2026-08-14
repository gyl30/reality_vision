#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include "hex.hpp"

namespace rv::core
{
namespace
{

int decode_hex_digit(const char value) noexcept
{
    if (value >= '0' && value <= '9')
    {
        return value - '0';
    }
    if (value >= 'a' && value <= 'f')
    {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F')
    {
        return value - 'A' + 10;
    }
    return -1;
}

}    // namespace

std::vector<std::uint8_t> decode_hex(const std::string_view input)
{
    if (input.empty() || input.size() % 2 != 0)
    {
        return {};
    }

    std::vector<std::uint8_t> output;
    output.reserve(input.size() / 2);
    for (std::size_t position = 0; position < input.size(); position += 2)
    {
        const auto high = decode_hex_digit(input[position]);
        const auto low = decode_hex_digit(input[position + 1]);
        if (high < 0 || low < 0)
        {
            return {};
        }
        output.push_back(static_cast<std::uint8_t>((high << 4U) | low));
    }
    return output;
}

}    // namespace rv::core

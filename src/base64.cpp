#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

#include <openssl/evp.h>

#include "base64.hpp"

namespace rv::core
{

std::vector<std::uint8_t> decode_base64_url(const std::string_view input)
{
    if (input.empty())
    {
        return {};
    }

    std::string normalized(input);
    for (char& character : normalized)
    {
        if (character == '-')
        {
            character = '+';
        }
        else if (character == '_')
        {
            character = '/';
        }
        else if ((character < 'A' || character > 'Z') && (character < 'a' || character > 'z') && (character < '0' || character > '9'))
        {
            return {};
        }
    }

    if (normalized.size() % 4 == 1)
    {
        return {};
    }
    while (normalized.size() % 4 != 0)
    {
        normalized.push_back('=');
    }

    std::size_t output_capacity = 0;
    if (!EVP_DecodedLength(&output_capacity, normalized.size()))
    {
        return {};
    }
    std::vector<std::uint8_t> output(output_capacity);
    std::size_t output_length = 0;
    if (!EVP_DecodeBase64(output.data(), &output_length, output.size(), reinterpret_cast<const std::uint8_t*>(normalized.data()), normalized.size()))
    {
        return {};
    }
    output.resize(output_length);
    return output;
}

}    // namespace rv::core

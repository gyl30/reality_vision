#include "base64.hpp"

#include <openssl/evp.h>

#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace rv::core
{

std::string base64::encode_to_string(const std::uint8_t* data, const std::uint32_t data_len)
{
    if (data == nullptr || data_len == 0)
    {
        return {};
    }

#if defined(OPENSSL_IS_BORINGSSL)
    std::size_t buffer_len = 0;
    if (!EVP_EncodedLength(&buffer_len, data_len) || buffer_len == 0)
    {
        return {};
    }

    std::vector<std::uint8_t> buffer(buffer_len);
    const auto output_len = EVP_EncodeBlock(buffer.data(), data, data_len);
    if (output_len != buffer_len - 1)
    {
        return {};
    }

    return {
        reinterpret_cast<const char*>(buffer.data()),
        output_len,
    };
#else
    if (data_len > INT_MAX)
    {
        return {};
    }

    const auto input_len = static_cast<std::size_t>(data_len);
    const auto groups = input_len / 3 + (input_len % 3 != 0 ? 1 : 0);
    if (groups > (std::numeric_limits<std::size_t>::max() - 1) / 4)
    {
        return {};
    }

    const auto output_len = groups * 4;
    if (output_len > static_cast<std::size_t>(INT_MAX))
    {
        return {};
    }

    std::string output(output_len + 1, '\0');
    const auto written = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(output.data()), data, static_cast<int>(data_len));
    if (written < 0 || static_cast<std::size_t>(written) != output_len)
    {
        return {};
    }

    output.resize(output_len);
    return output;
#endif
}

std::vector<std::uint8_t> base64::encode_to_bytes(const std::uint8_t* data, const std::uint32_t data_len)
{
    const auto encoded = encode_to_string(data, data_len);
    if (encoded.empty())
    {
        return {};
    }
    return {encoded.begin(), encoded.end()};
}

std::vector<std::uint8_t> base64::decode_to_bytes(const std::uint8_t* data, const std::uint32_t data_len)
{
    if (data == nullptr || data_len == 0 || data_len % 4 != 0)
    {
        return {};
    }

#if defined(OPENSSL_IS_BORINGSSL)
    std::size_t output_capacity = 0;
    if (!EVP_DecodedLength(&output_capacity, data_len))
    {
        return {};
    }

    std::vector<std::uint8_t> output(output_capacity);
    std::size_t output_len = 0;
    if (!EVP_DecodeBase64(output.data(), &output_len, output.size(), data, data_len) || output_len > output.size())
    {
        return {};
    }

    output.resize(output_len);
    return output;
#else
    if (data_len > INT_MAX)
    {
        return {};
    }

    std::size_t padding = 0;
    while (padding < data_len && data[data_len - padding - 1] == '=')
    {
        ++padding;
    }
    if (padding > 2)
    {
        return {};
    }

    const auto content_len = static_cast<std::size_t>(data_len) - padding;
    for (std::size_t index = 0; index < content_len; ++index)
    {
        if (data[index] == '=')
        {
            return {};
        }
    }

    const auto output_capacity = static_cast<std::size_t>(data_len / 4) * 3;
    std::vector<std::uint8_t> output(output_capacity);
    const auto decoded = EVP_DecodeBlock(output.data(), data, static_cast<int>(data_len));
    if (decoded < 0 || padding > output_capacity)
    {
        return {};
    }

    const auto decoded_len = static_cast<std::size_t>(decoded);
    const auto output_len = output_capacity - padding;
    if (decoded_len < output_len || decoded_len > output_capacity)
    {
        return {};
    }

    output.resize(output_len);
    return output;
#endif
}

std::string base64::decode_to_string(const std::uint8_t* data, const std::uint32_t data_len)
{
    const auto decoded = decode_to_bytes(data, data_len);
    if (decoded.empty())
    {
        return {};
    }

    return {
        reinterpret_cast<const char*>(decoded.data()),
        decoded.size(),
    };
}

std::string base64::encode_url_to_string(const std::uint8_t* data, const std::uint32_t data_len)
{
    if (data == nullptr || data_len == 0)
    {
        return {};
    }

    std::string result = encode_to_string(data, data_len);
    if (result.empty())
    {
        return {};
    }

    for (char& character : result)
    {
        if (character == '+')
        {
            character = '-';
        }
        else if (character == '/')
        {
            character = '_';
        }
    }

    while (!result.empty() && result.back() == '=')
    {
        result.pop_back();
    }

    return result;
}

std::vector<std::uint8_t> base64::decode_url_to_bytes(const std::uint8_t* data, std::uint32_t data_len)
{
    if (data == nullptr || data_len == 0)
    {
        return {};
    }

    std::string normalized;
    normalized.reserve(data_len + 2);

    for (std::uint32_t i = 0; i < data_len; ++i)
    {
        const auto ch = static_cast<char>(data[i]);

        if (ch == '-')
        {
            normalized.push_back('+');
        }
        else if (ch == '_')
        {
            normalized.push_back('/');
        }
        else if ((ch >= 'A' && ch <= 'Z') || (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'))
        {
            normalized.push_back(ch);
        }
        else
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

    return decode_to_bytes(reinterpret_cast<const std::uint8_t*>(normalized.data()), static_cast<std::uint32_t>(normalized.size()));
}
}    // namespace rv::core

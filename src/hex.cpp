#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

#include <boost/algorithm/hex.hpp>

#include "hex.hpp"

namespace rv::core
{

std::string hex::encode_to_string(const std::uint8_t* data, const std::uint32_t data_len)
{
    if (data == nullptr || data_len == 0)
    {
        return {};
    }

    if (static_cast<std::size_t>(data_len) > std::numeric_limits<std::size_t>::max() / 2)
    {
        return {};
    }

    std::string output;
    output.reserve(static_cast<std::size_t>(data_len) * 2);
    boost::algorithm::hex_lower(data, data + data_len, std::back_inserter(output));
    return output;
}

std::string hex::encode_to_string(const char* data, const std::uint32_t data_len)
{
    return encode_to_string(reinterpret_cast<const std::uint8_t*>(data), data_len);
}

std::vector<std::uint8_t> hex::encode_to_bytes(const std::uint8_t* data, const std::uint32_t data_len)
{
    const auto encoded = encode_to_string(data, data_len);
    if (encoded.empty())
    {
        return {};
    }
    return {encoded.begin(), encoded.end()};
}

std::vector<std::uint8_t> hex::decode_to_bytes(const std::uint8_t* data, const std::uint32_t data_len)
{
    if (data == nullptr || data_len == 0 || data_len % 2 != 0)
    {
        return {};
    }

    std::vector<std::uint8_t> output;
    output.reserve(data_len / 2);
    try
    {
        boost::algorithm::unhex(data, data + data_len, std::back_inserter(output));
    }
    catch (const boost::algorithm::hex_decode_error&)
    {
        return {};
    }
    return output;
}

std::vector<std::uint8_t> hex::decode_to_bytes(const char* data, const std::uint32_t data_len)
{
    return decode_to_bytes(reinterpret_cast<const std::uint8_t*>(data), data_len);
}

std::string hex::decode_to_string(const std::uint8_t* data, const std::uint32_t data_len)
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

std::string hex::decode_to_string(const char* data, const std::uint32_t data_len)
{
    return decode_to_string(reinterpret_cast<const std::uint8_t*>(data), data_len);
}

}    // namespace rv::core

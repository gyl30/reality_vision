#include <algorithm>
#include <cstdint>
#include <iostream>
#include <optional>
#include <limits>
#include <string>
#include <utility>
#include <vector>

#include <boost/program_options.hpp>
#include <boost/uuid/string_generator.hpp>
#include <boost/uuid/uuid.hpp>

#include "base64.hpp"
#include "config.hpp"
#include "hex.hpp"

namespace rv::app
{
// namespace

std::optional<config> parse_config(const int argc, char* argv[])
{
    config result;

    std::string server_public_key;
    std::string short_id_hex;
    std::string uuid;
    std::string socks_username;
    std::string socks_password;

    boost::program_options::options_description description("configuration");
    description.add_options()("help,h", "show help")("self_test", "run protocol tests")(
        "server", boost::program_options::value<std::string>(&result.server)->required(), "reality server host")(
        "port", boost::program_options::value<std::uint16_t>(&result.port)->required(), "reality server port")(
        "server_name", boost::program_options::value<std::string>(&result.server_name)->required(), "reality server name")(
        "server_public_key", boost::program_options::value<std::string>(&server_public_key)->required(), "reality server public key")(
        "short_id", boost::program_options::value<std::string>(&short_id_hex)->required(), "reality short id")(
        "uuid", boost::program_options::value<std::string>(&uuid)->required(), "vless uuid")(
        "socks_port", boost::program_options::value<std::uint16_t>(&result.socks_port)->required(), "socks5 listen port")(
        "socks_username", boost::program_options::value<std::string>(&socks_username), "socks5 username")(
        "socks_password", boost::program_options::value<std::string>(&socks_password), "socks5 password");

    boost::program_options::variables_map values;
    try
    {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, description), values);
        if (values.contains("help"))
        {
            std::cout << description << '\n';
            return std::nullopt;
        }
        if (values.contains("self_test"))
        {
            result.self_test = true;
            return result;
        }
        boost::program_options::notify(values);
    }
    catch (const boost::program_options::error& error)
    {
        std::cerr << "configuration error: " << error.what() << '\n';
        return std::nullopt;
    }

    if (result.port == 0)
    {
        std::cerr << "--port must be between 1 and 65535\n";
        return std::nullopt;
    }

    if (result.socks_port == 0)
    {
        std::cerr << "--socks_port must be between 1 and 65535\n";
        return std::nullopt;
    }
    const bool has_username = values.contains("socks_username");
    const bool has_password = values.contains("socks_password");
    if (has_username != has_password)
    {
        std::cerr << "--socks_username and --socks_password must be used together\n";
        return std::nullopt;
    }

    if (has_username)
    {
        if (socks_username.empty() || socks_password.empty() || socks_username.size() > 255 || socks_password.size() > 255)
        {
            std::cerr << "socks5 credentials must contain 1 to 255 bytes\n";
            return std::nullopt;
        }
        result.socks_credentials = rv::socks5::credentials{
            .username = std::move(socks_username),
            .password = std::move(socks_password),
        };
    }

    if (server_public_key.size() > std::numeric_limits<std::uint32_t>::max())
    {
        std::cerr << "--server_public_key is too long\n";
        return std::nullopt;
    }
    const auto public_key = core::base64::decode_url_to_bytes(reinterpret_cast<const std::uint8_t*>(server_public_key.data()),
                                                              static_cast<std::uint32_t>(server_public_key.size()));
    if (public_key.size() != result.server_public_key.size())
    {
        std::cerr << "--server_public_key must decode to exactly 32 bytes\n";
        return std::nullopt;
    }
    if (short_id_hex.size() > std::numeric_limits<std::uint32_t>::max())
    {
        std::cerr << "--short_id is too long\n";
        return std::nullopt;
    }
    const auto short_id = core::hex::decode_to_bytes(short_id_hex.data(), static_cast<std::uint32_t>(short_id_hex.size()));
    if (short_id.size() != result.short_id.size())
    {
        std::cerr << "--short_id must decode to exactly 8 bytes\n";
        return std::nullopt;
    }

    std::ranges::copy(public_key, result.server_public_key.begin());
    std::ranges::copy(short_id, result.short_id.begin());
    try
    {
        const auto parsed_uuid = boost::uuids::string_generator{}(uuid);
        std::ranges::copy(parsed_uuid, result.user_id.begin());
    }
    catch (const std::runtime_error&)
    {
        std::cerr << "--uuid must be a valid UUID\n";
        return std::nullopt;
    }

    return result;
}

}    // namespace rv::app

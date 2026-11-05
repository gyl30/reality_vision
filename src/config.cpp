#include <string>
#include <cstdint>
#include <utility>
#include <iostream>
#include <algorithm>

#include <boost/program_options.hpp>
#include <boost/uuid/string_generator.hpp>

#include "hex.hpp"
#include "base64.hpp"
#include "config.hpp"

namespace rv::app
{
namespace
{

bool validate_listen_and_server_ports(const config& configuration)
{
    if (configuration.reality_server_port == 0)
    {
        std::cerr << "--port must be between 1 and 65535\n";
        return false;
    }
    if (configuration.socks_listen_port == 0 && configuration.redirect_listen_port == 0 && configuration.tproxy_listen_port == 0 &&
        !configuration.tun_enabled)
    {
        std::cerr << "at least one of --socks_port, --redirect_port, --tproxy_port, or --tun must be configured\n";
        return false;
    }
    if (configuration.tun_enabled && configuration.worker_count != 1)
    {
        std::cerr << "--tun requires --workers 1\n";
        return false;
    }
    if (configuration.tun_enabled && configuration.tun_mtu < 576)
    {
        std::cerr << "--tun_mtu must be between 576 and 65535\n";
        return false;
    }
    return true;
}

bool parse_socks_credentials(const boost::program_options::variables_map& options, std::string username, std::string password, config& configuration)
{
    const bool has_username = options.contains("socks_username");
    const bool has_password = options.contains("socks_password");
    if (has_username != has_password)
    {
        std::cerr << "--socks_username and --socks_password must be used together\n";
        return false;
    }
    if (!has_username)
    {
        return true;
    }
    if (configuration.socks_listen_port == 0)
    {
        std::cerr << "--socks_username and --socks_password require --socks_port\n";
        return false;
    }
    if (username.empty() || password.empty() || username.size() > socks5::kMaximumCredentialLength ||
        password.size() > socks5::kMaximumCredentialLength)
    {
        std::cerr << "socks5 credentials must contain 1 to 255 bytes\n";
        return false;
    }

    configuration.socks_credentials = rv::socks5::credentials{
        .username = std::move(username),
        .password = std::move(password),
    };
    return true;
}

bool decode_reality_public_key(const std::string& encoded, config& configuration)
{
    const auto decoded = core::decode_base64_url(encoded);
    if (decoded.size() != configuration.reality_server_public_key.size())
    {
        std::cerr << "--server_public_key must decode to exactly 32 bytes\n";
        return false;
    }

    std::ranges::copy(decoded, configuration.reality_server_public_key.begin());
    return true;
}

bool decode_reality_short_id(const std::string& encoded, config& configuration)
{
    const auto maximum_hex_length = configuration.reality_short_id.size() * 2;
    if (encoded.size() > maximum_hex_length || encoded.size() % 2 != 0)
    {
        std::cerr << "--short_id must contain an even number of hexadecimal characters up to " << maximum_hex_length << '\n';
        return false;
    }

    configuration.reality_short_id.fill(0);
    if (encoded.empty())
    {
        return true;
    }

    const auto decoded = core::decode_hex(encoded);
    if (decoded.size() != encoded.size() / 2)
    {
        std::cerr << "--short_id contains invalid hexadecimal characters\n";
        return false;
    }

    std::ranges::copy(decoded, configuration.reality_short_id.begin());
    return true;
}

bool decode_vless_user_id(const std::string& uuid, config& configuration)
{
    try
    {
        const auto parsed = boost::uuids::string_generator{}(uuid);
        std::ranges::copy(parsed, configuration.vless_user_id.begin());
        return true;
    }
    catch (const std::runtime_error&)
    {
        std::cerr << "--uuid must be a valid UUID\n";
        return false;
    }
}

}    // namespace

std::expected<config, config_exit_code> parse_config(const int argc, char* argv[])
{
    config configuration;
    std::string server_public_key;
    std::string short_id;
    std::string uuid;
    std::string socks_username;
    std::string socks_password;

    boost::program_options::options_description description("configuration");
    description.add_options()("help,h", "show help")("self_test", "run protocol tests")(
        "server", boost::program_options::value<std::string>(&configuration.reality_server_host)->required(), "reality server host")(
        "port", boost::program_options::value<std::uint16_t>(&configuration.reality_server_port)->required(), "reality server port")(
        "server_name", boost::program_options::value<std::string>(&configuration.reality_server_name)->required(), "reality server name")(
        "server_public_key", boost::program_options::value<std::string>(&server_public_key)->required(), "reality server public key")(
        "short_id", boost::program_options::value<std::string>(&short_id)->required(), "reality short id")(
        "uuid", boost::program_options::value<std::string>(&uuid)->required(), "vless uuid")(
        "socks_port", boost::program_options::value<std::uint16_t>(&configuration.socks_listen_port), "socks5 listen port")(
        "redirect_port", boost::program_options::value<std::uint16_t>(&configuration.redirect_listen_port), "TCP REDIRECT listen port")(
        "tproxy_port", boost::program_options::value<std::uint16_t>(&configuration.tproxy_listen_port), "TCP TPROXY listen port")(
        "tun", "enable Linux TUN inbound")(
        "tun_name", boost::program_options::value<std::string>(&configuration.tun_name)->default_value(configuration.tun_name), "TUN device name")(
        "tun_mtu", boost::program_options::value<std::uint16_t>(&configuration.tun_mtu)->default_value(configuration.tun_mtu), "TUN device MTU")(
        "mark", boost::program_options::value<std::uint32_t>(&configuration.outbound_mark), "SO_MARK for outbound REALITY connections (Linux)")(
        "socks_username", boost::program_options::value<std::string>(&socks_username), "socks5 username")(
        "socks_password", boost::program_options::value<std::string>(&socks_password), "socks5 password")(
        "workers", boost::program_options::value<std::size_t>(&configuration.worker_count)->default_value(kDefaultWorkerCount), "number of io_context workers");

    boost::program_options::variables_map options;
    try
    {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, description), options);
        if (options.contains("help"))
        {
            std::cout << description << '\n';
            return std::unexpected(config_exit_code::kSuccess);
        }
        if (options.contains("self_test"))
        {
            configuration.self_test = true;
            return configuration;
        }
        boost::program_options::notify(options);
    }
    catch (const boost::program_options::error& error)
    {
        std::cerr << "configuration error: " << error.what() << '\n';
        return std::unexpected(config_exit_code::kFailure);
    }

    if (configuration.worker_count == 0)
    {
        std::cerr << "--workers must be greater than zero\n";
        return std::unexpected(config_exit_code::kFailure);
    }
    configuration.tun_enabled = options.contains("tun");
    if (!validate_listen_and_server_ports(configuration) ||
        !parse_socks_credentials(options, std::move(socks_username), std::move(socks_password), configuration) ||
        !decode_reality_public_key(server_public_key, configuration) || !decode_reality_short_id(short_id, configuration) ||
        !decode_vless_user_id(uuid, configuration))
    {
        return std::unexpected(config_exit_code::kFailure);
    }

    return configuration;
}

}    // namespace rv::app

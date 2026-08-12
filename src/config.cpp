#include "config.hpp"

#include "base64.hpp"
#include "hex.hpp"

#include <boost/program_options.hpp>
#include <boost/uuid/string_generator.hpp>

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <ranges>
#include <string>
#include <utility>

namespace rv::app
{
namespace
{

namespace po = boost::program_options;

bool validate_listen_and_server_ports(const config& configuration)
{
    if (configuration.reality_server_port == 0)
    {
        std::cerr << "--port must be between 1 and 65535\n";
        return false;
    }
    if (configuration.socks_listen_port == 0 && configuration.redirect_listen_port == 0 && configuration.tproxy_listen_port == 0)
    {
        std::cerr << "at least one of --socks_port, --redirect_port, or --tproxy_port must be configured\n";
        return false;
    }
    return true;
}

bool validate_resource_limits(const config& configuration)
{
    if (configuration.maximum_tcp_sessions == 0 || configuration.maximum_udp_flows == 0 || configuration.maximum_pending_handshakes == 0 ||
        configuration.worker_count == 0)
    {
        std::cerr << "resource limits must be greater than zero\n";
        return false;
    }
    return true;
}

bool parse_socks_credentials(const po::variables_map& options, std::string username, std::string password, config& configuration)
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

    po::options_description description("configuration");
    description.add_options()("help,h", "show help")("self_test", "run protocol tests")(
        "server", po::value<std::string>(&configuration.reality_server_host)->required(), "reality server host")(
        "port", po::value<std::uint16_t>(&configuration.reality_server_port)->required(), "reality server port")(
        "server_name", po::value<std::string>(&configuration.reality_server_name)->required(), "reality server name")(
        "server_public_key", po::value<std::string>(&server_public_key)->required(), "reality server public key")(
        "short_id", po::value<std::string>(&short_id)->required(), "reality short id")(
        "uuid", po::value<std::string>(&uuid)->required(), "vless uuid")(
        "socks_port", po::value<std::uint16_t>(&configuration.socks_listen_port), "socks5 listen port")(
        "redirect_port", po::value<std::uint16_t>(&configuration.redirect_listen_port), "TCP REDIRECT listen port")(
        "tproxy_port", po::value<std::uint16_t>(&configuration.tproxy_listen_port), "TCP TPROXY listen port")(
        "socks_username", po::value<std::string>(&socks_username), "socks5 username")(
        "socks_password", po::value<std::string>(&socks_password), "socks5 password")(
        "max_tcp_sessions",
        po::value<std::size_t>(&configuration.maximum_tcp_sessions)->default_value(kDefaultMaximumTcpSessions),
        "maximum active TCP sessions")("max_udp_flows",
                                       po::value<std::size_t>(&configuration.maximum_udp_flows)->default_value(kDefaultMaximumUdpFlows),
                                       "maximum active UDP flows")(
        "max_pending_handshakes",
        po::value<std::size_t>(&configuration.maximum_pending_handshakes)->default_value(kDefaultMaximumPendingHandshakes),
        "maximum concurrent upstream handshakes")("workers",
                                                   po::value<std::size_t>(&configuration.worker_count)->default_value(kDefaultWorkerCount),
                                                   "number of io_context workers");

    po::variables_map options;
    try
    {
        po::store(po::parse_command_line(argc, argv, description), options);
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
        po::notify(options);
    }
    catch (const po::error& error)
    {
        std::cerr << "configuration error: " << error.what() << '\n';
        return std::unexpected(config_exit_code::kFailure);
    }

    if (!validate_listen_and_server_ports(configuration) || !validate_resource_limits(configuration) ||
        !parse_socks_credentials(options, std::move(socks_username), std::move(socks_password), configuration) ||
        !decode_reality_public_key(server_public_key, configuration) || !decode_reality_short_id(short_id, configuration) ||
        !decode_vless_user_id(uuid, configuration))
    {
        return std::unexpected(config_exit_code::kFailure);
    }

    return configuration;
}

}    // namespace rv::app

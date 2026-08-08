#ifndef reality_vision_config_hpp
#define reality_vision_config_hpp

#include "socks5_protocol.hpp"

#include <array>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>

namespace rv::app
{

struct config
{
    bool self_test{false};
    std::string reality_server_host;
    std::uint16_t reality_server_port = 0;
    std::string reality_server_name;
    std::array<std::uint8_t, 32> reality_server_public_key{};
    std::array<std::uint8_t, 8> reality_short_id{};
    std::array<std::uint8_t, 16> vless_user_id{};

    std::uint16_t socks_listen_port = 0;
    std::uint16_t redirect_listen_port = 0;
    std::uint16_t tproxy_listen_port = 0;
    std::optional<rv::socks5::credentials> socks_credentials;
};

enum class config_exit_code : int
{
    success = 0,
    failure = 1,
};

[[nodiscard]] std::expected<config, config_exit_code> parse_config(int argc, char* argv[]);

}    // namespace rv::app

#endif    // reality_vision_config_hpp

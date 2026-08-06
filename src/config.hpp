#ifndef reality_vision_config_hpp
#define reality_vision_config_hpp

#include "socks5_protocol.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <string>

namespace rv::app
{

struct config
{
    bool self_test{false};
    std::string server;
    std::uint16_t port = 0;
    std::string server_name;
    std::array<std::uint8_t, 32> server_public_key{};
    std::array<std::uint8_t, 8> short_id{};
    std::array<std::uint8_t, 16> user_id{};

    std::uint16_t socks_port = 0;
    std::optional<rv::socks5::credentials> socks_credentials;
};

[[nodiscard]] std::optional<config> parse_config(int argc, char* argv[]);

}    // namespace rv::app

#endif    // reality_vision_config_hpp

#ifndef REALITY_VISION_CONFIG_HPP
#define REALITY_VISION_CONFIG_HPP

#include <array>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <expected>

#include "crypto.hpp"
#include "vless_header.hpp"
#include "reality_config.hpp"
#include "socks5_protocol.hpp"

namespace rv::app
{

inline constexpr std::size_t kDefaultWorkerCount = 1;

struct config
{
    bool self_test{false};
    std::string reality_server_host;
    std::uint16_t reality_server_port = 0;
    std::string reality_server_name;
    std::array<std::uint8_t, crypto::kX25519KeySize> reality_server_public_key{};
    std::array<std::uint8_t, reality::kShortIdSize> reality_short_id{};
    std::array<std::uint8_t, vless::kUserIdSize> vless_user_id{};

    std::uint16_t socks_listen_port = 0;
    std::uint16_t redirect_listen_port = 0;
    std::uint16_t tproxy_listen_port = 0;
    bool tun_enabled = false;
    std::string tun_name = "rv-tun";
    std::uint16_t tun_mtu = 1500;
    std::optional<rv::socks5::credentials> socks_credentials;

    std::size_t worker_count = kDefaultWorkerCount;
};

enum class config_exit_code : int
{
    kSuccess = 0,
    kFailure = 1,
};

[[nodiscard]] std::expected<config, config_exit_code> parse_config(int argc, char* argv[]);

}    // namespace rv::app

#endif    // REALITY_VISION_CONFIG_HPP

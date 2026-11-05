#ifndef REALITY_VISION_CONFIG_HPP
#define REALITY_VISION_CONFIG_HPP

#include <array>
#include <vector>
#include <chrono>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <expected>

#include <boost/asio/ip/tcp.hpp>

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
    // 由 service 启动时解析一次；之后所有出站连接只使用这些地址，避免全局 TUN 下解析 DNS 再次进入代理形成回环。
    std::vector<boost::asio::ip::tcp::endpoint> reality_server_endpoints;
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
    // 出站 REALITY 连接的 SO_MARK，0 表示不设置；用于全局透明代理/TUN 的策略路由绕行。
    std::uint32_t outbound_mark = 0;
    // TCP 中继双向都没有数据时关闭连接，0 表示不限制；默认值与 Xray connIdle 一致。
    std::chrono::seconds tcp_idle_timeout{300};

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

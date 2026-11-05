#ifndef REALITY_VISION_XUDP_CODEC_HPP
#define REALITY_VISION_XUDP_CODEC_HPP

#include <span>
#include <array>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <boost/system/error_code.hpp>

#include "network_address.hpp"

// Xray XUDP：VLESS command=Mux、目标 v1.mux.cool:666 的 Mux.Cool 帧，会话 ID 固定为 0，
// 每个数据报携带目的地址（上行）或来源地址（下行）。
namespace rv::xudp
{

inline constexpr std::size_t kGlobalIdSize = 8;
// 与 Xray xudp.PacketWriter 一致：length + 666 > 8192 的数据报被跳过；服务端拒绝超过 8192 bytes 的数据报。
inline constexpr std::size_t kMaximumPayloadSize = 8192 - 666;
inline constexpr std::size_t kFrameLengthSize = 2;

using global_id = std::array<std::uint8_t, kGlobalIdSize>;

struct endpoint
{
    net::address address;
    std::uint16_t port{};
};

enum class frame_kind : std::uint8_t
{
    kData,
    kDiscard,
    kEnd,
};

struct frame_metadata
{
    frame_kind kind{frame_kind::kEnd};
    bool has_data{false};
    std::optional<endpoint> source;
};

[[nodiscard]] std::vector<std::uint8_t> encode_new_frame(const endpoint& destination,
                                                         const global_id& id,
                                                         std::span<const std::uint8_t> payload,
                                                         boost::system::error_code& ec);
[[nodiscard]] std::vector<std::uint8_t> encode_keep_frame(const endpoint& destination,
                                                          std::span<const std::uint8_t> payload,
                                                          boost::system::error_code& ec);

// metadata 为长度前缀之后的帧元数据；与 Xray xudp.PacketReader 一致，Keep 之外的未知状态视为流结束。
[[nodiscard]] frame_metadata parse_frame_metadata(std::span<const std::uint8_t> metadata, boost::system::error_code& ec);

}    // namespace rv::xudp

#endif    // REALITY_VISION_XUDP_CODEC_HPP

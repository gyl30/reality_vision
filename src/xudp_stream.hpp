#ifndef REALITY_VISION_XUDP_STREAM_HPP
#define REALITY_VISION_XUDP_STREAM_HPP

#include <span>
#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <string_view>

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "xudp_codec.hpp"
#include "vision_stream.hpp"

namespace rv::xudp
{

struct datagram
{
    endpoint source;
    std::vector<std::uint8_t> payload;
};

// 与 Xray xudp.GetGlobalID 相同的用途：同一客户端源地址在进程内得到稳定 ID，重连时服务端复用同一出站 UDP 映射。
[[nodiscard]] global_id make_global_id(std::string_view client_source);

// 一条 VLESS(Vision) 连接承载同一客户端源地址发往任意目标的 UDP 数据报。
class xudp_stream
{
   public:
    xudp_stream(vision::vision_stream vision, global_id id, std::string session_id);

    // 调用方保证同一时刻只有一个写操作。
    [[nodiscard]] boost::asio::awaitable<void> write_datagram(const endpoint& destination,
                                                              std::span<const std::uint8_t> payload,
                                                              boost::system::error_code& ec);
    // 返回服务端转发的回包及其来源地址；收到 End 时 ec 为 eof。
    [[nodiscard]] boost::asio::awaitable<datagram> read_datagram(boost::system::error_code& ec);

    void shutdown() noexcept;

   private:
    vision::vision_stream vision_;
    global_id id_{};
    std::optional<endpoint> first_destination_;
    std::string session_id_;
};

}    // namespace rv::xudp

#endif    // REALITY_VISION_XUDP_STREAM_HPP

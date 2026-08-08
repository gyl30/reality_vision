#ifndef REALITY_VISION_VLESS_UDP_STREAM_HPP
#define REALITY_VISION_VLESS_UDP_STREAM_HPP

#include "reality_stream.hpp"
#include "vless_header.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace rv::vless
{

class vless_udp_stream
{
   public:
    [[nodiscard]] static boost::asio::awaitable<std::optional<vless_udp_stream>> connect(reality::reality_stream reality,
                                                                                         client_config configuration,
                                                                                         std::string session_id,
                                                                                         boost::system::error_code& ec);

    [[nodiscard]] boost::asio::awaitable<void> write_datagram(std::span<const std::uint8_t> payload, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<std::vector<std::uint8_t>> read_datagram(boost::system::error_code& ec);

    void shutdown() noexcept;

   private:
    vless_udp_stream(reality::reality_stream reality, std::string session_id);

    [[nodiscard]] boost::asio::awaitable<void> read_response_header(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> read_exact(std::span<std::uint8_t> output, boost::system::error_code& ec);

    reality::reality_stream reality_;
    bool response_header_pending_{true};
    std::string session_id_;
};

}    // namespace rv::vless

#endif    // REALITY_VISION_VLESS_UDP_STREAM_HPP

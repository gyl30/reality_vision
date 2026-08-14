#ifndef REALITY_VISION_VLESS_STREAM_HPP
#define REALITY_VISION_VLESS_STREAM_HPP

#include <span>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include "vless_header.hpp"
#include "reality_stream.hpp"

namespace rv::vless
{

class vless_stream
{
   public:
    [[nodiscard]] static boost::asio::awaitable<std::optional<vless_stream>> connect(reality::reality_stream reality,
                                                                                     client_config configuration,
                                                                                     std::string session_id,
                                                                                     boost::system::error_code& ec);

    [[nodiscard]] boost::asio::awaitable<std::size_t> read(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> write(std::span<const std::uint8_t> input, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> shutdown_send(boost::system::error_code& ec);

    void switch_receive_to_raw(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> write_final_tls_and_switch_to_raw(std::span<const std::uint8_t> final_plaintext,
                                                                                 boost::system::error_code& ec);

    void shutdown() noexcept;

   private:
    vless_stream(reality::reality_stream reality, std::string session_id);
    reality::reality_stream reality_;
    bool response_header_pending_{true};
    std::string session_id_;
};

}    // namespace rv::vless

#endif    // REALITY_VISION_VLESS_STREAM_HPP

#ifndef REALITY_VISION_VLESS_STREAM_HPP
#define REALITY_VISION_VLESS_STREAM_HPP

#include "reality_stream.hpp"
#include "vless_header.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>

namespace rv::vless
{

class vless_stream
{
   public:
    [[nodiscard]] static boost::asio::awaitable<std::optional<vless_stream>> connect(reality::reality_stream lower,
                                                                                     client_config config,
                                                                                     std::string id,
                                                                                     boost::system::error_code& ec);

    [[nodiscard]] boost::asio::awaitable<std::size_t> async_read_some(std::span<std::uint8_t> output, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_write_all(std::span<const std::uint8_t> input, boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_shutdown_send(boost::system::error_code& ec);

    [[nodiscard]] bool switch_receive_to_raw(boost::system::error_code& ec);
    [[nodiscard]] boost::asio::awaitable<void> async_write_final_tls_and_switch(std::span<const std::uint8_t> final_plaintext,
                                                                                boost::system::error_code& ec);

    void shutdown() noexcept;

   private:
    vless_stream(reality::reality_stream lower, std::string log);
    [[nodiscard]] boost::asio::awaitable<void> read_response_header(boost::system::error_code& ec);

    reality::reality_stream lower_;
    bool response_pending_{true};
    std::string id_;
};

}    // namespace rv::vless

#endif

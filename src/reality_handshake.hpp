#ifndef REALITY_VISION_REALITY_HANDSHAKE_HPP
#define REALITY_VISION_REALITY_HANDSHAKE_HPP

#include "reality_config.hpp"
#include "reality_record.hpp"
#include "tcp_byte_stream.hpp"

#include <boost/asio/awaitable.hpp>
#include <boost/system/error_code.hpp>

#include <optional>
#include <string>

namespace rv::reality
{

struct handshake_result
{
    record_key receive_key;
    record_key send_key;
};

[[nodiscard]] boost::asio::awaitable<std::optional<handshake_result>> perform_client_handshake(net::tcp_byte_stream& tcp,
                                                                                               const client_config& configuration,
                                                                                               const std::string& session_id,
                                                                                               boost::system::error_code& ec);

}    // namespace rv::reality

#endif    // REALITY_VISION_REALITY_HANDSHAKE_HPP

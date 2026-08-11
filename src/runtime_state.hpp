#ifndef REALITY_VISION_RUNTIME_STATE_HPP
#define REALITY_VISION_RUNTIME_STATE_HPP

#include <cstddef>

namespace rv::app
{

struct runtime_state
{
    std::size_t active_tcp_sessions{};
    std::size_t active_udp_flows{};
    std::size_t pending_handshakes{};
};

}    // namespace rv::app

#endif    // REALITY_VISION_RUNTIME_STATE_HPP

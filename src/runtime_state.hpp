#ifndef REALITY_VISION_RUNTIME_STATE_HPP
#define REALITY_VISION_RUNTIME_STATE_HPP

#include <cstddef>
#include <atomic>

namespace rv::app
{

struct runtime_state
{
    std::atomic<std::size_t> active_tcp_sessions{};
    std::atomic<std::size_t> active_udp_flows{};
    std::atomic<std::size_t> pending_handshakes{};

    static bool try_acquire(std::atomic<std::size_t>& counter, const std::size_t maximum) noexcept
    {
        auto current = counter.load(std::memory_order_relaxed);
        while (current < maximum &&
               !counter.compare_exchange_weak(current, current + 1, std::memory_order_relaxed, std::memory_order_relaxed))
        {
        }
        return current < maximum;
    }

    bool try_acquire_tcp(const std::size_t maximum) noexcept { return try_acquire(active_tcp_sessions, maximum); }
    bool try_acquire_udp(const std::size_t maximum) noexcept { return try_acquire(active_udp_flows, maximum); }
    bool try_acquire_handshake(const std::size_t maximum) noexcept { return try_acquire(pending_handshakes, maximum); }

    void release_tcp() noexcept { active_tcp_sessions.fetch_sub(1, std::memory_order_relaxed); }
    void release_udp() noexcept { active_udp_flows.fetch_sub(1, std::memory_order_relaxed); }
    void release_handshake() noexcept { pending_handshakes.fetch_sub(1, std::memory_order_relaxed); }
};

}    // namespace rv::app

#endif    // REALITY_VISION_RUNTIME_STATE_HPP

#ifndef HPP_GUARD_MDNSPP_DETAIL_RECV_LOOP_H
#define HPP_GUARD_MDNSPP_DETAIL_RECV_LOOP_H

#include "mdnspp/policy.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/recv_filter.h"

#include <span>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace mdnspp::detail {

/// Effectively-infinite silence timeout for peers without silence semantics
/// (observer, monitor) -- the recv_loop runs until stop().
inline constexpr std::chrono::milliseconds infinite_silence_timeout =
    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::hours(24 * 365));

template <policy_like P>
class recv_loop
{
    using clock_type = std::chrono::steady_clock;

public:
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    // Returns true if the packet was relevant (resets silence timer),
    // false to ignore (timer continues counting down).
    using packet_handler = move_only_function<bool(const recv_metadata &, std::span<std::byte>)>;

    // Invoked when the socket reports a fatal receive error; the loop stops re-arming.
    using error_handler = move_only_function<void(std::error_code)>;

    recv_loop(
        socket_type &socket,
        timer_type &timer,
        std::chrono::milliseconds silence_timeout,
        packet_handler on_packet,
        move_only_function<void()> on_silence,
        uint32_t receive_ttl_minimum = 0,
        ttl_unknown_policy unknown_ttl_policy = ttl_unknown_policy::accept,
        error_handler on_error = nullptr)
        : m_silence_pending(false)
        , m_receive_ttl_minimum(receive_ttl_minimum)
        , m_transient_failures(0)
        , m_ttl_unknown_policy(unknown_ttl_policy)
        , m_stopped(false)
        , m_silence_timeout(silence_timeout)
        , m_silence_deadline()
        , m_socket(socket)
        , m_timer(timer)
        , m_on_silence(std::move(on_silence))
        , m_on_packet(std::move(on_packet))
        , m_on_error(std::move(on_error))
    {
    }

    ~recv_loop()
    {
        stop();
    }

    // Non-copyable, non-movable (owns async callbacks by address)
    recv_loop(const recv_loop &) = delete;
    recv_loop &operator=(const recv_loop &) = delete;
    recv_loop(recv_loop &&) = delete;
    recv_loop &operator=(recv_loop &&) = delete;

    void start()
    {
        arm_silence_timer();
        arm_receive();
    }

    void stop()
    {
        if(m_stopped.exchange(true))
            return;
        m_timer.cancel();
        m_socket.close();
    }

private:
    // The packet, silence and error callbacks may stop the loop re-entrantly,
    // so every function that arms the socket or the timer checks m_stopped first.
    void arm_receive()
    {
        if(m_stopped.load(std::memory_order_acquire))
            return;
        m_socket.async_receive(
            [this](std::error_code ec, const recv_metadata &meta, std::span<std::byte> data)
            {
                if(m_stopped.load(std::memory_order_acquire))
                    return;
                if(ec)
                    on_receive_error(ec);
                else
                    on_receive(meta, data);
            });
    }

    void on_receive_error(std::error_code ec)
    {
        if(is_fatal_receive_error(ec))
        {
            if(m_on_error)
                m_on_error(ec);
        }
        else if(++m_transient_failures > 1)
            defer_rearm();
        else
            arm_receive();
    }

    void on_receive(const recv_metadata &meta, std::span<std::byte> data)
    {
        m_transient_failures = 0;
        if(ttl_accepted(meta, m_receive_ttl_minimum, m_ttl_unknown_policy) && m_on_packet(meta, data))
            arm_silence_timer();
        arm_receive();
    }

    void arm_silence_timer()
    {
        m_silence_deadline = clock_type::now() + m_silence_timeout;
        wait_silence(m_silence_timeout);
    }

    void wait_silence(std::chrono::milliseconds delay)
    {
        if(m_stopped.load(std::memory_order_acquire))
            return;
        m_silence_pending = true;
        m_timer.expires_after(delay);
        m_timer.async_wait(
            [this](std::error_code ec)
            {
                if(ec || m_stopped.load(std::memory_order_acquire))
                    return;
                m_silence_pending = false;
                m_on_silence();
            });
    }

    // Re-purposes the shared timer for the transient backoff delay, then
    // restores a still-owed silence wait for the remainder of its absolute
    // deadline before re-arming the receive. m_silence_pending stays true
    // across the implicit cancellation by expires_after: it means "a silence
    // wait is owed", not "a wait is armed". No receive is armed during the
    // backoff, so no packet can re-arm the silence wait underneath it.
    void defer_rearm()
    {
        if(m_stopped.load(std::memory_order_acquire))
            return;
        m_timer.expires_after(transient_backoff_delay(m_transient_failures));
        m_timer.async_wait(
            [this](std::error_code ec)
            {
                if(ec || m_stopped.load(std::memory_order_acquire))
                    return;
                if(m_silence_pending)
                {
                    auto now = clock_type::now();
                    auto remaining = m_silence_deadline > now
                        ? std::chrono::ceil<std::chrono::milliseconds>(m_silence_deadline - now)
                        : std::chrono::milliseconds::zero();
                    wait_silence(remaining);
                }
                arm_receive();
            });
    }

    bool m_silence_pending;
    uint32_t m_receive_ttl_minimum;
    uint32_t m_transient_failures;
    ttl_unknown_policy m_ttl_unknown_policy;
    std::atomic<bool> m_stopped;
    std::chrono::milliseconds m_silence_timeout;
    clock_type::time_point m_silence_deadline;
    socket_type &m_socket;
    timer_type &m_timer;
    move_only_function<void()> m_on_silence;
    packet_handler m_on_packet;
    error_handler m_on_error;
};

}

#endif

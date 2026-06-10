#ifndef HPP_GUARD_MDNSPP_RECV_LOOP_H
#define HPP_GUARD_MDNSPP_RECV_LOOP_H

#include "mdnspp/policy.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/detail/compat.h"

#include <span>
#include <atomic>
#include <chrono>
#include <cstdint>

namespace mdnspp {

template <Policy P>
class recv_loop
{
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
        : m_receive_ttl_minimum(receive_ttl_minimum)
        , m_ttl_unknown_policy(unknown_ttl_policy)
        , m_stopped(false)
        , m_silence_timeout(silence_timeout)
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
        {
            return; // already stopped — idempotent
        }
        m_timer.cancel();
        m_socket.close();
    }

private:
    void arm_receive()
    {
        if(m_stopped.load(std::memory_order_acquire))
        {
            return;
        }
        m_socket.async_receive(
            [this](std::error_code ec, const recv_metadata &meta, std::span<std::byte> data)
            {
                if(m_stopped.load(std::memory_order_acquire))
                {
                    return;
                }
                if(ec)
                {
                    if(is_fatal(ec))
                    {
                        if(m_on_error)
                            m_on_error(ec);
                        return;
                    }
                    arm_receive();
                    return;
                }
                if(meta.ttl.has_value())
                {
                    if(static_cast<uint32_t>(*meta.ttl) < m_receive_ttl_minimum)
                    {
                        arm_receive();
                        return;
                    }
                }
                else if(m_ttl_unknown_policy == ttl_unknown_policy::reject)
                {
                    arm_receive();
                    return;
                }
                bool relevant = m_on_packet(meta, data);
                if(relevant)
                    arm_silence_timer();
                arm_receive();
            });
    }

    void arm_silence_timer()
    {
        m_timer.expires_after(m_silence_timeout);
        m_timer.async_wait(
            [this](std::error_code ec)
            {
                if(ec || m_stopped.load(std::memory_order_acquire))
                {
                    return;
                }
                m_on_silence();
            });
    }

    // Errors that mean the socket can no longer deliver packets; everything
    // else (e.g. ECONNRESET from a stray ICMP, ENOBUFS) is transient.
    static bool is_fatal(std::error_code ec) noexcept
    {
        return ec == std::errc::operation_canceled
            || ec == std::errc::bad_file_descriptor;
    }

    uint32_t m_receive_ttl_minimum;
    ttl_unknown_policy m_ttl_unknown_policy;
    std::atomic<bool> m_stopped;
    std::chrono::milliseconds m_silence_timeout;
    socket_type &m_socket;
    timer_type &m_timer;
    move_only_function<void()> m_on_silence;
    packet_handler m_on_packet;
    error_handler m_on_error;
};

}

#endif

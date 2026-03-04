#ifndef HPP_GUARD_MDNSPP_RECV_LOOP_H
#define HPP_GUARD_MDNSPP_RECV_LOOP_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/timer_policy.h"
#include <atomic>
#include <chrono>
#include <functional>
#include <span>
#include <vector>

namespace mdnspp {

template <SocketPolicy S, TimerPolicy T>
class recv_loop
{
public:
    using packet_handler = std::function<void(std::span<std::byte>, endpoint)>;

    recv_loop(
        S socket,
        T timer,
        std::chrono::milliseconds silence_timeout,
        packet_handler on_packet,
        std::function<void()> on_silence)
        : m_socket(std::move(socket))
        , m_timer(std::move(timer))
        , m_silence_timeout(silence_timeout)
        , m_on_packet(std::move(on_packet))
        , m_on_silence(std::move(on_silence))
        , m_stopped(false)
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

    // Accessors — expose internal policies for owners who moved their policy into the loop.
    // service_server uses socket() to send responses after moving m_socket into recv_loop.
    S       &socket()       noexcept { return m_socket; }
    const S &socket() const noexcept { return m_socket; }
    T       &timer()        noexcept { return m_timer; }

private:
    void arm_receive()
    {
        if(m_stopped.load(std::memory_order_acquire))
        {
            return;
        }
        m_buffer.resize(4096);
        m_socket.async_receive(
            [this](std::span<std::byte> data, endpoint ep)
            {
                if(m_stopped.load(std::memory_order_acquire))
                {
                    return;
                }
                m_on_packet(data, ep);
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

    S m_socket;
    T m_timer;
    std::chrono::milliseconds m_silence_timeout;
    packet_handler m_on_packet;
    std::function<void()> m_on_silence;
    std::atomic<bool> m_stopped;
    std::vector<std::byte> m_buffer;
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_RECV_LOOP_H

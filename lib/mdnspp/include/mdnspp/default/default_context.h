#ifndef HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_CONTEXT_H
#define HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_CONTEXT_H

// compute_next_timeout_ms() and fire_expired_timers() are defined in default_timer.h
// because they dereference default_timer, which is incomplete here.

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/poll_set.h"
#include "mdnspp/detail/wakeup_fd.h"
#include "mdnspp/detail/post_queue.h"
#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/recv_datagram.h"
#include "mdnspp/detail/executor_owner.h"
#include "mdnspp/detail/socket_registry.h"

#include <span>
#include <array>
#include <atomic>
#include <chrono>
#include <vector>
#include <cstddef>
#include <utility>
#include <algorithm>
#include <system_error>

namespace mdnspp {

class default_timer;

class default_context
{
public:
    default_context()
        : m_wsa{}
        , m_stopped{false}
        , m_wakeup{}
        , m_post_queue{[this] { m_wakeup.notify(); }}
        , m_recv_buf{}
        , m_recv_meta(detail::reserved_metadata())
    {
        m_wakeup.create();
    }

    default_context(const default_context &) = delete;
    default_context &operator=(const default_context &) = delete;
    default_context(default_context &&) = delete;
    default_context &operator=(default_context &&) = delete;

    void run()
    {
        m_owner.claim();
        bool keep_going = true;
        while(keep_going && !m_stopped.load(std::memory_order_acquire))
            keep_going = run_once(compute_next_timeout_ms(std::chrono::steady_clock::now()), false);
    }

    void poll_one()
    {
        m_owner.claim();
        run_once(0, true);
    }

    void stop()
    {
        m_stopped.store(true, std::memory_order_release);
        m_wakeup.notify();
    }

    void restart()
    {
        m_stopped.store(false, std::memory_order_release);
        m_wakeup.drain();
        m_post_queue.clear();
    }

    void post(detail::move_only_function<void()> fn)
    {
        m_post_queue.post(std::move(fn));
    }

    void register_socket(detail::native_socket_t fd)
    {
        m_sockets.add(fd);
    }

#ifdef _WIN32
    void register_socket(detail::native_socket_t fd, LPFN_WSARECVMSG fn_wsarecvmsg)
    {
        m_sockets.add(fd, fn_wsarecvmsg);
    }
#endif

    void deregister_socket(detail::native_socket_t fd)
    {
        m_sockets.remove(fd);
    }

    void arm_receive(detail::native_socket_t fd, detail::receive_handler handler)
    {
        m_sockets.arm(fd, std::move(handler));
    }

    void register_timer(default_timer *t)
    {
        m_owner.assert_current();
        if(std::find(m_timers.begin(), m_timers.end(), t) == m_timers.end())
            m_timers.push_back(t);
    }

    void deregister_timer(default_timer *t)
    {
        m_owner.assert_current();
        std::erase(m_timers, t);
    }

    int compute_next_timeout_ms(std::chrono::steady_clock::time_point now) const;

    void fire_expired_timers();

private:
    // winsock_guard must be the first member so winsock is initialized before any socket
    winsock_guard m_wsa;
    std::atomic<bool> m_stopped;
    detail::wakeup_fd m_wakeup;
    detail::post_queue<> m_post_queue;
    detail::socket_registry m_sockets;
    detail::poll_set m_poll;
    detail::executor_owner m_owner;
    std::vector<default_timer *> m_timers;
    std::vector<detail::native_socket_t> m_ready;
    std::array<std::byte, detail::max_udp_payload> m_recv_buf;
    recv_metadata m_recv_meta;

    // single_step ends the pass after the first kind of work, as poll_one does
    bool run_once(int timeout_ms, bool single_step)
    {
        if(m_poll.wait(m_wakeup.native(), m_sockets, timeout_ms) < 0)
            return detail::poll_set::interrupted();
        if(m_poll.wake_ready() || m_post_queue.pending())
        {
            m_wakeup.drain();
            if(m_stopped.load(std::memory_order_acquire))
                return false;
            m_post_queue.drain();
            if(single_step)
                return true;
        }
        const bool received = dispatch_receives();
        if(!single_step || !received)
            fire_expired_timers();
        return true;
    }

    bool dispatch_receives()
    {
        m_poll.ready_sockets(m_ready);
        for(const detail::native_socket_t fd : m_ready)
            deliver_datagram(fd);
        return !m_ready.empty();
    }

    void deliver_datagram(detail::native_socket_t fd)
    {
        if(!m_sockets.armed(fd))
            return;
        const detail::datagram_result result = read_datagram(fd);
        if(result.would_block || result.truncated)
            return;
        detail::receive_handler handler = m_sockets.take_handler(fd);
        if(result.ec)
            handler(result.ec, recv_metadata{}, std::span<std::byte>{});
        else
            handler(std::error_code{}, m_recv_meta, std::span<std::byte>{m_recv_buf.data(), result.size});
    }

    detail::datagram_result read_datagram(detail::native_socket_t fd)
    {
#ifdef _WIN32
        return detail::recv_datagram(fd, m_recv_buf, m_sockets.wsarecvmsg(fd), m_recv_meta);
#else
        return detail::recv_datagram(fd, m_recv_buf, m_recv_meta);
#endif
    }
};

}

#endif

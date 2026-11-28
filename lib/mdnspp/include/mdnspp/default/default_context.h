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
#include "mdnspp/detail/executor_owner.h"
#include "mdnspp/detail/socket_registry.h"
#include "mdnspp/detail/datagram_dispatch.h"

#include <atomic>
#include <chrono>
#include <vector>
#include <utility>
#include <algorithm>
#include <system_error>

namespace mdnspp {

class default_timer;

class default_context
{
    struct checked
    {
    };

public:
    default_context()
        : default_context(checked{}, std::error_code{})
    {
    }

    explicit default_context(std::error_code &ec)
        : m_wsa{ec}
        , m_stopped{false}
        , m_wakeup{}
        , m_post_queue{[this] { m_wakeup.notify(); }}
        , m_sockets{}
        , m_poll{}
        , m_owner{}
        , m_timers{}
        , m_receiver{m_sockets}
    {
        if(!ec)
            m_wakeup.create(ec);
    }

    default_context(const default_context &) = delete;
    default_context &operator=(const default_context &) = delete;
    default_context(default_context &&) = delete;
    default_context &operator=(default_context &&) = delete;

    void run(std::error_code &ec)
    {
        const detail::executor_claim claim = m_owner.claim();
        ec.clear();
        while(!m_stopped.load(std::memory_order_acquire) && !ec)
            if(wait(compute_next_timeout_ms(std::chrono::steady_clock::now()), ec))
                dispatch_step(false);
    }

    void poll_one(std::error_code &ec)
    {
        const detail::executor_claim claim = m_owner.claim();
        ec.clear();
        while(!wait(0, ec))
            if(ec)
                return;
        dispatch_step(true);
    }

    void run()
    {
        std::error_code ec;
        run(ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::default_context::run");
    }

    void poll_one()
    {
        std::error_code ec;
        poll_one(ec);
        if(ec)
            throw std::system_error(ec, "mdnspp::default_context::poll_one");
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
    detail::datagram_dispatcher m_receiver;

    default_context(checked, std::error_code ec)
        : default_context(ec)
    {
        if(ec)
            throw std::system_error(ec, "mdnspp::default_context");
    }

    bool wait(int timeout_ms, std::error_code &ec)
    {
        return m_poll.wait(m_wakeup.native(), m_sockets, timeout_ms, ec);
    }

    // single_step ends the pass after the first kind of work, as poll_one does
    void dispatch_step(bool single_step)
    {
        if(m_poll.wake_ready() || m_post_queue.pending())
        {
            m_wakeup.drain();
            if(m_stopped.load(std::memory_order_acquire))
                return;
            m_post_queue.drain();
            if(single_step)
                return;
        }
        const bool received = m_receiver.dispatch(m_poll);
        if(!single_step || !received)
            fire_expired_timers();
    }
};

}

#endif

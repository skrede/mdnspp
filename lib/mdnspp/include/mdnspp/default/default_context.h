#ifndef HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_CONTEXT_H
#define HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_CONTEXT_H

// default_context — standalone poll-based event loop for default_policy.
// No ASIO includes. POSIX/Linux primary, Windows via #ifdef guards.
//
// NOTE: compute_next_timeout_ms() and fire_expired_timers() are declared here
// but defined in default_timer.h (after default_timer is fully defined), because
// they dereference default_timer*. Include default_timer.h to get the full
// implementation — that header includes this one first.

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/platform.h"
#include "mdnspp/detail/wakeup_fd.h"
#include "mdnspp/detail/post_queue.h"
#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/recv_datagram.h"

#include <span>
#include <array>
#include <atomic>
#include <chrono>
#include <thread>
#include <vector>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <system_error>

namespace mdnspp {

class default_timer;

class default_context
{
public:
    /// Throws std::system_error when the wakeup channel cannot be created.
    default_context()
        : m_post_queue{[this] { m_wakeup.notify(); }}
    {
        m_wakeup.create();
    }

    default_context(const default_context &) = delete;
    default_context &operator=(const default_context &) = delete;
    default_context(default_context &&) = delete;
    default_context &operator=(default_context &&) = delete;

    /// Block until stop() is called, processing I/O and expired timers.
    /// Call restart() before re-entering run() after a stop().
    void run()
    {
#ifndef NDEBUG
        if(!m_owner_set.exchange(true, std::memory_order_acq_rel))
            m_owner_thread = std::this_thread::get_id();
#endif
        while(!m_stopped.load(std::memory_order_acquire))
        {
            const auto now = std::chrono::steady_clock::now();
            const int timeout = compute_next_timeout_ms(now);
            const int rc = do_poll(timeout);

            if(rc < 0)
            {
#ifndef _WIN32
                if(errno == EINTR)
                    continue; // EINTR — retry
#endif
                break;
            }

            if(wakeup_readable() || m_post_queue.pending())
            {
                m_wakeup.drain();
                if(m_stopped.load(std::memory_order_acquire))
                    break;
                m_post_queue.drain();
            }

            if(any_socket_readable())
                dispatch_receives();

            fire_expired_timers();
        }
    }

    void poll_one()
    {
#ifndef NDEBUG
        if(!m_owner_set.exchange(true, std::memory_order_acq_rel))
            m_owner_thread = std::this_thread::get_id();
#endif
        const int rc = do_poll(0);
        if(rc < 0)
            return;

        if(wakeup_readable() || m_post_queue.pending())
        {
            m_wakeup.drain();
            if(m_stopped.load(std::memory_order_acquire))
                return;
            m_post_queue.drain();
            return;
        }

        if(any_socket_readable())
        {
            dispatch_receives();
            return;
        }

        fire_expired_timers();
    }

    /// Signal the event loop to stop. Thread-safe and idempotent.
    void stop()
    {
        m_stopped.store(true, std::memory_order_release);
        m_wakeup.notify();
    }

    /// Reset the stopped flag so run() can be called again after stop().
    /// Clears any stale work left over from the previous run.
    void restart()
    {
        m_stopped.store(false, std::memory_order_release);
        m_wakeup.drain();
        m_post_queue.clear();
    }

    /// Safe to call from any thread; the item runs on the executor thread.
    void post(detail::move_only_function<void()> fn)
    {
        m_post_queue.post(std::move(fn));
    }

    // -----------------------------------------------------------------------
    // Internal interface — called by default_socket / default_timer
    // -----------------------------------------------------------------------

    void register_socket(detail::native_socket_t fd,
                          move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler
#ifdef _WIN32
                          , LPFN_WSARECVMSG fn_wsarecvmsg = nullptr
#endif
                          )
    {
        // Replace if already registered (e.g. async_receive re-arms)
        for(auto &entry : m_sockets)
        {
            if(entry.fd == fd)
            {
                entry.handler = std::move(handler);
#ifdef _WIN32
                entry.fn_wsarecvmsg = fn_wsarecvmsg;
#endif
                return;
            }
        }
#ifdef _WIN32
        m_sockets.push_back({fd, std::move(handler), fn_wsarecvmsg});
#else
        m_sockets.push_back({fd, std::move(handler)});
#endif
    }

    void deregister_socket(detail::native_socket_t fd)
    {
        std::erase_if(m_sockets, [fd](const auto &e) { return e.fd == fd; });
    }

    void register_timer(default_timer *t)
    {
        assert_executor_thread();
        if(std::find(m_timers.begin(), m_timers.end(), t) == m_timers.end())
            m_timers.push_back(t);
    }

    void deregister_timer(default_timer *t)
    {
        assert_executor_thread();
        std::erase(m_timers, t);
    }

    // -----------------------------------------------------------------------
    // Private helpers (declared here; timer-dependent ones defined in
    // default_timer.h after default_timer is fully defined)
    // -----------------------------------------------------------------------
    int compute_next_timeout_ms(std::chrono::steady_clock::time_point now) const;
    void fire_expired_timers();

private:
    struct socket_entry
    {
        detail::native_socket_t fd{detail::invalid_socket};
        move_only_function<void(std::error_code, const recv_metadata &, std::span<std::byte>)> handler;
#ifdef _WIN32
        LPFN_WSARECVMSG fn_wsarecvmsg{nullptr};
#endif
    };

    void assert_executor_thread() const noexcept
    {
#ifndef NDEBUG
        // Only enforce once an executor thread has been established (first run()/poll_one()).
        if(m_owner_set.load(std::memory_order_acquire))
            assert(std::this_thread::get_id() == m_owner_thread &&
                   "default_context: m_timers accessed from wrong thread");
#endif
    }

    // winsock_guard MUST be the first member — initialised before any sockets.
    winsock_guard m_wsa{};
    std::atomic<bool> m_stopped{false};
    detail::wakeup_fd m_wakeup;
    detail::post_queue<> m_post_queue;
    std::vector<socket_entry> m_sockets;
    std::vector<default_timer*> m_timers;
    std::array<std::byte, detail::max_udp_payload> m_recv_buf{};

    // Poll state — rebuilt each do_poll() call.
    std::vector<pollfd> m_pollfds;

#ifndef NDEBUG
    // Lazily initialized on first call to run() — captures the executor thread id.
    std::atomic<bool> m_owner_set{false};
    std::thread::id m_owner_thread{};
#endif

    /// Build pollfd array, invoke poll, dispatch ready sockets.
    int do_poll(int timeout_ms)
    {
        m_pollfds.clear();
        m_pollfds.push_back({m_wakeup.native(), POLLIN, 0});
        for(const auto &entry : m_sockets)
            m_pollfds.push_back({entry.fd, POLLIN, 0});

        const auto nfds = static_cast<nfds_t>(m_pollfds.size());
        return detail::poll_sockets(m_pollfds.data(), nfds, timeout_ms);
    }

    bool wakeup_readable() const noexcept
    {
        return (m_pollfds[0].revents & POLLIN) != 0;
    }

    bool any_socket_readable() const noexcept
    {
        for(std::size_t i = 1; i < m_pollfds.size(); ++i)
            if(m_pollfds[i].revents & POLLIN)
                return true;
        return false;
    }

    void dispatch_receives()
    {
        for(std::size_t i = 1; i < m_pollfds.size(); ++i)
        {
            if(!(m_pollfds[i].revents & POLLIN))
                continue;

            const auto sock_idx = i - 1;
            if(sock_idx >= m_sockets.size() || !m_sockets[sock_idx].handler)
                continue;

            deliver_datagram(m_sockets[sock_idx]);
        }
    }

    void deliver_datagram(socket_entry &entry)
    {
        const detail::datagram_result result = read_datagram(entry);
        if(result.would_block || result.truncated)
            return;
        if(result.ec)
        {
            entry.handler(result.ec, recv_metadata{}, std::span<std::byte>{});
            return;
        }
        entry.handler(std::error_code{}, result.meta,
                      std::span<std::byte>{m_recv_buf.data(), result.size});
    }

    detail::datagram_result read_datagram(const socket_entry &entry)
    {
#ifdef _WIN32
        return detail::recv_datagram(entry.fd, m_recv_buf, entry.fn_wsarecvmsg);
#else
        return detail::recv_datagram(entry.fd, m_recv_buf);
#endif
    }
};

}

#endif

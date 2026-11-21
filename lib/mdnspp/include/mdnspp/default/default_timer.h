#ifndef HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_TIMER_H
#define HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_TIMER_H

// Holds the out-of-line definitions of default_context::compute_next_timeout_ms and fire_expired_timers, which
// dereference default_timer; include this header rather than default_context.h alone.

#include "mdnspp/default/default_context.h"

#include "mdnspp/policy.h"

#include "mdnspp/detail/compat.h"

#include <chrono>
#include <limits>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <system_error>

namespace mdnspp {

class default_timer
{
public:
    explicit default_timer(default_context &ctx)
        : m_ctx{ctx}
    {
    }

    explicit default_timer(default_context &ctx, std::error_code &)
        : m_ctx{ctx}
    {
    }

    ~default_timer()
    {
        m_ctx.deregister_timer(this);
    }

    default_timer(const default_timer &) = delete;
    default_timer &operator=(const default_timer &) = delete;
    default_timer(default_timer &&) = delete;
    default_timer &operator=(default_timer &&) = delete;

    // Drops a pending handler without calling it, as mock_timer does; the asio and inproc timers complete it with
    // operation_canceled instead.
    void expires_after(std::chrono::milliseconds dur)
    {
        m_pending_handler = nullptr;
        m_deadline = std::chrono::steady_clock::now() + dur;
        m_ctx.register_timer(this);
    }

    void async_wait(detail::move_only_function<void(std::error_code)> handler)
    {
        m_pending_handler = std::move(handler);
    }

    void cancel()
    {
        if(m_pending_handler)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::make_error_code(std::errc::operation_canceled));
        }
        m_ctx.deregister_timer(this);
    }

    void fire_if_expired()
    {
        if(m_pending_handler && std::chrono::steady_clock::now() >= m_deadline)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::error_code{});
        }
    }

    std::chrono::steady_clock::time_point deadline() const noexcept
    {
        return m_deadline;
    }

    bool has_pending() const noexcept
    {
        return m_pending_handler != nullptr;
    }

private:
    default_context &m_ctx;
    std::chrono::steady_clock::time_point m_deadline{};
    detail::move_only_function<void(std::error_code)> m_pending_handler;
};

static_assert(timer_like<default_timer>, "default_timer must satisfy timer_like — check expires_after/async_wait/cancel");

inline int default_context::compute_next_timeout_ms(std::chrono::steady_clock::time_point now) const
{
    m_owner.assert_current();
    int min_ms = -1; // -1 = no pending timer, poll blocks indefinitely
    for(const default_timer *t : m_timers)
    {
        if(!t->has_pending())
            continue;

        const auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
            t->deadline() - now);

        const int64_t raw = diff.count();
        const int ms = static_cast<int>(std::clamp<int64_t>(raw, 0, std::numeric_limits<int>::max()));

        if(min_ms < 0 || ms < min_ms)
            min_ms = ms;
    }
    return min_ms;
}

inline void default_context::fire_expired_timers()
{
    m_owner.assert_current();
    // A handler may destroy or register timers, so each snapshot entry is re-checked before dispatch.
    const std::vector<default_timer *> timers = m_timers;
    for(default_timer *t : timers)
        if(std::ranges::find(m_timers, t) != m_timers.end())
            t->fire_if_expired();
}

}

#endif

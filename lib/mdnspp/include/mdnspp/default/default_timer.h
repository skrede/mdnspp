#ifndef HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_TIMER_H
#define HPP_GUARD_MDNSPP_DEFAULT_DEFAULT_TIMER_H

// default_timer — deadline-based timer satisfying timer_like, backed by default_context.
// Include this header (not default_context.h directly) to get the full implementation,
// as it provides the out-of-line definitions of default_context::compute_next_timeout_ms
// and default_context::fire_expired_timers that dereference default_timer*.

#include "mdnspp/policy.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/default/default_context.h"

#include <chrono>
#include <utility>
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

    /// Set (or reset) the deadline. Silently drops any pending handler WITHOUT
    /// calling it — matching mock_timer semantics required by recv_loop.
    void expires_after(std::chrono::milliseconds dur)
    {
        m_pending_handler = nullptr; // DROP — do not call
        m_deadline = std::chrono::steady_clock::now() + dur;
        m_ctx.register_timer(this);
    }

    /// Register the completion handler. Fired by default_context when the deadline passes.
    void async_wait(detail::move_only_function<void(std::error_code)> handler)
    {
        m_pending_handler = std::move(handler);
    }

    /// Cancel the pending handler, firing it with operation_canceled.
    /// No-op if no handler is pending.
    void cancel()
    {
        if(m_pending_handler)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::make_error_code(std::errc::operation_canceled));
        }
        m_ctx.deregister_timer(this);
    }

    // -----------------------------------------------------------------------
    // Internal interface — called by default_context
    // -----------------------------------------------------------------------

    /// Fire the pending handler with success if the deadline has passed.
    void fire_if_expired()
    {
        if(m_pending_handler && std::chrono::steady_clock::now() >= m_deadline)
        {
            auto h = std::exchange(m_pending_handler, nullptr);
            h(std::error_code{});
        }
    }

    [[nodiscard]] std::chrono::steady_clock::time_point deadline() const noexcept
    {
        return m_deadline;
    }

    [[nodiscard]] bool has_pending() const noexcept
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
    assert_executor_thread();
    int min_ms = -1; // -1 = no pending timer, poll blocks indefinitely
    for(const default_timer *t : m_timers)
    {
        if(!t->has_pending())
            continue;

        const auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
            t->deadline() - now);

        // Clamp to 0: already-expired timers fire on the next poll cycle.
        const auto raw = diff.count();
        const int ms = static_cast<int>(raw > 0 ? raw : 0);

        if(min_ms < 0 || ms < min_ms)
            min_ms = ms;
    }
    return min_ms;
}

inline void default_context::fire_expired_timers()
{
    assert_executor_thread();
    // Snapshot to avoid iterator invalidation if a handler calls register/deregister.
    const auto timers = m_timers;
    for(default_timer *t : timers)
        t->fire_if_expired();
}

}

#endif

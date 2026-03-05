#ifndef HPP_GUARD_MDNSPP_DEFAULT_TIMER_H
#define HPP_GUARD_MDNSPP_DEFAULT_TIMER_H

// DefaultTimer — deadline-based timer satisfying TimerLike, backed by DefaultContext.
// Include this header (not default_context.h directly) to get the full implementation,
// as it provides the out-of-line definitions of DefaultContext::compute_next_timeout_ms
// and DefaultContext::fire_expired_timers that dereference DefaultTimer*.

#include "mdnspp/policy.h"

#include "mdnspp/default/default_context.h"

#include <chrono>
#include <utility>
#include <functional>
#include <system_error>

namespace mdnspp {

class DefaultTimer
{
public:
    explicit DefaultTimer(DefaultContext &ctx)
        : m_ctx{ctx}
    {
    }

    explicit DefaultTimer(DefaultContext &ctx, std::error_code &)
        : m_ctx{ctx}
    {
    }

    ~DefaultTimer()
    {
        m_ctx.deregister_timer(this);
    }

    DefaultTimer(const DefaultTimer &) = delete;
    DefaultTimer &operator=(const DefaultTimer &) = delete;
    DefaultTimer(DefaultTimer &&) = delete;
    DefaultTimer &operator=(DefaultTimer &&) = delete;

    /// Set (or reset) the deadline. Silently drops any pending handler WITHOUT
    /// calling it — matching MockTimer semantics required by recv_loop.
    void expires_after(std::chrono::milliseconds dur)
    {
        m_pending_handler = nullptr; // DROP — do not call
        m_deadline = std::chrono::steady_clock::now() + dur;
        m_ctx.register_timer(this);
    }

    /// Register the completion handler. Fired by DefaultContext when the deadline passes.
    void async_wait(std::function<void(std::error_code)> handler)
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
    // Internal interface — called by DefaultContext
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
    DefaultContext &m_ctx;
    std::chrono::steady_clock::time_point m_deadline{};
    std::function<void(std::error_code)> m_pending_handler;
};

static_assert(TimerLike<DefaultTimer>, "DefaultTimer must satisfy TimerLike — check expires_after/async_wait/cancel");

inline int DefaultContext::compute_next_timeout_ms(std::chrono::steady_clock::time_point now) const
{
    int min_ms = -1; // -1 = no pending timer, poll blocks indefinitely
    for(const DefaultTimer *t : m_timers)
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

inline void DefaultContext::fire_expired_timers()
{
    // Snapshot to avoid iterator invalidation if a handler calls register/deregister.
    const auto timers = m_timers;
    for(DefaultTimer *t : timers)
        t->fire_if_expired();
}

}

#endif

#ifndef HPP_GUARD_MDNSPP_NATIVE_NATIVE_TIMER_H
#define HPP_GUARD_MDNSPP_NATIVE_NATIVE_TIMER_H

// NativeTimer — deadline-based timer satisfying TimerLike, backed by NativeContext.
// Include this header (not native_context.h directly) to get the full implementation,
// as it provides the out-of-line definitions of NativeContext::compute_next_timeout_ms
// and NativeContext::fire_expired_timers that dereference NativeTimer*.

#include "mdnspp/native/native_context.h"
#include "mdnspp/policy.h"

#include <chrono>
#include <functional>
#include <system_error>
#include <utility>

namespace mdnspp {

// ---------------------------------------------------------------------------
// NativeTimer — satisfies TimerLike concept
// ---------------------------------------------------------------------------
class NativeTimer
{
public:
    /// Construct from a NativeContext. Stores reference; does not register yet.
    explicit NativeTimer(NativeContext &ctx)
        : m_ctx{ctx}
    {
    }

    /// error_code-based constructor — timer construction is infallible.
    explicit NativeTimer(NativeContext &ctx, std::error_code &)
        : m_ctx{ctx}
    {
    }

    /// Destructor deregisters this timer from the context.
    ~NativeTimer()
    {
        m_ctx.deregister_timer(this);
    }

    NativeTimer(const NativeTimer &) = delete;
    NativeTimer &operator=(const NativeTimer &) = delete;
    NativeTimer(NativeTimer &&) = delete;
    NativeTimer &operator=(NativeTimer &&) = delete;

    // -----------------------------------------------------------------------
    // TimerLike interface
    // -----------------------------------------------------------------------

    /// Set (or reset) the deadline. Silently drops any pending handler WITHOUT
    /// calling it — matching MockTimer semantics required by recv_loop.
    void expires_after(std::chrono::milliseconds dur)
    {
        m_pending_handler = nullptr; // DROP — do not call
        m_deadline = std::chrono::steady_clock::now() + dur;
        m_ctx.register_timer(this);
    }

    /// Register the completion handler. Fired by NativeContext when the deadline passes.
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
    // Internal interface — called by NativeContext
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
    NativeContext &m_ctx;
    std::chrono::steady_clock::time_point m_deadline{};
    std::function<void(std::error_code)> m_pending_handler;
};

// ---------------------------------------------------------------------------
// Concept conformance check
// ---------------------------------------------------------------------------
static_assert(TimerLike<NativeTimer>,
              "NativeTimer must satisfy TimerLike — check expires_after/async_wait/cancel");

} // namespace mdnspp

// ---------------------------------------------------------------------------
// Out-of-line definitions of NativeContext methods that dereference NativeTimer*.
// These must appear here, after NativeTimer is fully defined.
// ---------------------------------------------------------------------------
namespace mdnspp {

inline int NativeContext::compute_next_timeout_ms(std::chrono::steady_clock::time_point now) const
{
    int min_ms = -1; // -1 = no pending timer, poll blocks indefinitely
    for(const NativeTimer *t : m_timers)
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

inline void NativeContext::fire_expired_timers()
{
    // Snapshot to avoid iterator invalidation if a handler calls register/deregister.
    const auto timers = m_timers;
    for(NativeTimer *t : timers)
        t->fire_if_expired();
}

}

#endif

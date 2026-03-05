#ifndef HPP_GUARD_MDNSPP_OBSERVER_H
#define HPP_GUARD_MDNSPP_OBSERVER_H

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/detail/recv_loop.h"
#include "mdnspp/detail/dns_wire.h"

#include <memory>
#include <atomic>
#include <functional>
#include <span>
#include <chrono>
#include <cassert>
#include <system_error>
#include <utility>

#ifdef ASIO_STANDALONE
#include "mdnspp/asio/asio_completion.h"
#endif

namespace mdnspp {

// observer<P> — mDNS multicast listener
//
// Policy-based class template parameterized on:
//   P — Policy: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. observer(ex, callback)        — direct constructor (throwing)
//      observer(ex, callback, ec)    — non-throwing overload (ec set on failure)
//   2. async_observe([on_done])      — arms recv_loop; returns immediately
//                                      on_done fires with error_code{} when stop() is called
//   3. stop()                        — idempotent; sets stop flag, fires completion handler
//   4. ~observer()                   — destroys recv_loop for RAII safety
//
// Observer is a pure listener — no queries sent, no responses built.
// All parsed records are delivered to the callback with the sender endpoint.
// Malformed packets are silently skipped.
//
// stop() is callback-safe: it sets the atomic stop flag but does NOT destroy
// the recv_loop. The recv_loop is cleaned up in ~observer(), which is never
// called from within the recv_loop callback chain.
//
// No inheritance. No std::mutex. Single timer (unlike service_server).

template <Policy P>
class observer
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;
    using record_callback = std::function<void(mdns_record_variant, endpoint)>;

    /// Completion callback fired once when stop() is called.
    /// Receives error_code (always success).
    using completion_handler = std::function<void(std::error_code)>;

    // Non-copyable
    observer(const observer &) = delete;
    observer &operator=(const observer &) = delete;

    // Movable only before async_observe() is called (m_loop must be null).
    // Moving a started observer is a logic error (recv_loop callbacks capture this).
    observer(observer &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_callback(std::move(other.m_callback))
        , m_on_completion(std::move(other.m_on_completion))
        , m_loop(std::move(other.m_loop))
        , m_stopped(other.m_stopped.load(std::memory_order_acquire))
    {
        assert(other.m_loop == nullptr); // source must not have been started
        other.m_stopped.store(true, std::memory_order_release);
    }

    observer &operator=(observer &&) = delete; // move-assign not needed; omit for simplicity

    ~observer()
    {
        m_stopped.store(true, std::memory_order_release);
        m_loop.reset(); // safe — destructor is never called from within callback chain
    }

    // Throwing constructor — constructs socket and timer from executor.
    // Throws on construction failure (e.g. socket bind error).
    explicit observer(executor_type ex, record_callback callback)
        : m_socket(ex)
        , m_timer(ex)
        , m_callback(std::move(callback))
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    // Non-throwing constructor — sets ec on failure instead of throwing.
    // ec is the last parameter, matching ASIO convention.
    observer(executor_type ex, record_callback callback, std::error_code &ec)
        : m_socket(ex, ec)
        , m_timer(ex)
        , m_callback(std::move(callback))
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

#ifndef ASIO_STANDALONE
    // Non-template callback overload — used by NativePolicy and MockPolicy users.
    // async_observe() — arms the recv_loop and returns immediately.
    // on_done fires with error_code{} when stop() is called (or empty if omitted).
    // Incoming multicast packets are parsed and each record delivered to the callback.
    // Must only be called once; calling async_observe() twice is a logic error.
    void async_observe(completion_handler on_done = {})
    {
        assert(m_loop == nullptr); // can only start once
        // Only store if non-empty — prevents wrapping an empty std::function in
        // move_only_function (which would evaluate as truthy but throw on call).
        if(on_done)
            m_on_completion = std::move(on_done);
        do_observe();
    }
#endif

#ifdef ASIO_STANDALONE
    /// Zero-argument fire-and-forget overload for ASIO users — equivalent to async_observe(asio::detached).
    void async_observe()
    {
        async_observe(asio::detached);
    }

    /// ASIO completion token overload — accepts use_future, use_awaitable, deferred, or any callable.
    /// Fires when stop() is called with signature void(std::error_code).
    /// NativePolicy users (no ASIO_STANDALONE) use the non-template overload above instead.
    template <asio::completion_token_for<void(std::error_code)> CompletionToken>
    auto async_observe(CompletionToken &&token)
    {
        return asio::async_initiate<CompletionToken, void(std::error_code)>(
            [this](auto handler)
            {
                auto work = asio::make_work_guard(handler);

                // Type-erase into completion_handler, dispatching via the handler's executor.
                // The work guard is moved into the final dispatch lambda so it is released
                // only AFTER the handler executes, preventing premature io_context::run() return.
                m_on_completion = [h = std::move(handler), w = std::move(work)](
                    std::error_code ec) mutable
                    {
                        mdnspp::dispatch_completion(std::move(h), std::move(w), ec);
                    };

                do_observe();
            },
            token);
    }
#endif

    // stop() — idempotent; fires the completion handler, then sets the stop flag.
    //
    // Does NOT call m_loop.reset() here — this is critical for callback-safe stop.
    // The recv_loop remains alive until ~observer() destroys it, ensuring that
    // any in-progress callback chain can complete without accessing a dangling loop.
    void stop()
    {
        if(m_stopped.exchange(true, std::memory_order_acq_rel))
            return; // already stopped — idempotent

        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::error_code{});
    }

    // Accessors — observer owns socket and timer directly.
    const socket_type &socket() const noexcept { return m_socket; }
    socket_type &socket() noexcept { return m_socket; }
    const timer_type &timer() const noexcept { return m_timer; }
    timer_type &timer() noexcept { return m_timer; }

private:
    // Common observe body — assumes m_on_completion is already set.
    // Creates and starts the recv_loop with "infinite" silence timeout.
    void do_observe()
    {
        m_loop = std::make_unique<recv_loop<P>>(
            m_socket,
            m_timer,
            std::chrono::hours(24 * 365), // "infinite" silence timeout (run until stop())
            [this](std::span<std::byte> data, endpoint sender) -> bool
            {
                on_packet(data, sender);
                return true; // observer wants all traffic; always reset timer
            },
            []()
            {
                /* no-op on silence */
            });

        m_loop->start();
    }

    // Called by recv_loop for every incoming packet.
    // Checks the stop flag, then walks the DNS frame and delivers each record.
    void on_packet(std::span<std::byte> data, endpoint sender)
    {
        if(m_stopped.load(std::memory_order_acquire))
            return;

        detail::walk_dns_frame(
            std::span<const std::byte>(data.data(), data.size()),
            sender,
            [this, sender](mdns_record_variant rec)
            {
                if(!m_stopped.load(std::memory_order_acquire))
                    m_callback(std::move(rec), sender);
            });
    }

    socket_type m_socket;       // socket used for receiving multicast packets
    timer_type m_timer;         // passed to recv_loop for silence-timeout tracking
    record_callback m_callback; // called once per successfully parsed record
    // Move-only function: supports both copyable std::function handlers (NativePolicy)
    // and move-only ASIO coroutine handlers (use_awaitable via ASIO_STANDALONE path).
    std::move_only_function<void(std::error_code)>
    m_on_completion;                      // fires once when stop() is called
    std::unique_ptr<recv_loop<P>> m_loop; // continuous listener (null until async_observe())
    std::atomic<bool> m_stopped;          // idempotent stop flag
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_OBSERVER_H

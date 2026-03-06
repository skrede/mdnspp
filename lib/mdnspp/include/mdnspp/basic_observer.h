#ifndef HPP_GUARD_MDNSPP_BASIC_OBSERVER_H
#define HPP_GUARD_MDNSPP_BASIC_OBSERVER_H

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/recv_loop.h"

#include <span>
#include <atomic>
#include <memory>
#include <chrono>
#include <cassert>
#include <utility>
#include <system_error>

namespace mdnspp {

// basic_observer<P> — mDNS multicast listener
//
// Policy-based class template parameterized on:
//   P — Policy: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. basic_observer(ex, on_record)       — direct constructor (throwing)
//      basic_observer(ex, on_record, ec)   — non-throwing overload (ec set on failure)
//   2. async_observe([on_done])            — arms recv_loop; returns immediately
//                                            on_done fires with error_code{} when stop() is called
//   3. stop()                              — idempotent; sets stop flag, fires completion handler
//   4. ~basic_observer()                   — destroys recv_loop for RAII safety
//
// basic_observer is a pure listener — no queries sent, no responses built.
// All parsed records are delivered to the callback with the sender endpoint.
// Malformed packets are silently skipped.
//
// stop() is callback-safe: it sets the atomic stop flag but does NOT destroy
// the recv_loop. The recv_loop is cleaned up in ~basic_observer(), which is never
// called from within the recv_loop callback chain.
//
// No inheritance. No std::mutex. Single timer (unlike basic_service_server).

template <Policy P>
class basic_observer
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;
    using record_callback = detail::move_only_function<void(const endpoint &, const mdns_record_variant &)>;

    /// Completion callback fired once when stop() is called.
    /// Receives error_code (always success).
    using completion_handler = detail::move_only_function<void(std::error_code)>;

    // Non-copyable
    basic_observer(const basic_observer &) = delete;
    basic_observer &operator=(const basic_observer &) = delete;

    // Movable only before async_observe() is called (m_loop must be null).
    // Moving a started basic_observer is a logic error (recv_loop callbacks capture this).
    basic_observer(basic_observer &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_on_record(std::move(other.m_on_record))
        , m_on_completion(std::move(other.m_on_completion))
        , m_loop(std::move(other.m_loop))
        , m_stopped(other.m_stopped.load(std::memory_order_acquire))
    {
        assert(other.m_loop == nullptr); // source must not have been started
        other.m_stopped.store(true, std::memory_order_release);
    }

    basic_observer &operator=(basic_observer &&) = delete; // move-assign not needed; omit for simplicity

    ~basic_observer()
    {
        m_stopped.store(true, std::memory_order_release);
        m_loop.reset(); // safe — destructor is never called from within callback chain
    }

    // Throwing constructor — constructs socket and timer from executor.
    // Throws on construction failure (e.g. socket bind error).
    explicit basic_observer(executor_type ex, record_callback on_record = {})
        : m_socket(ex)
        , m_timer(ex)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    // Non-throwing constructor — sets ec on failure instead of throwing.
    // ec is the last parameter, matching ASIO convention.
    basic_observer(executor_type ex, record_callback on_record, std::error_code &ec)
        : m_socket(ex, ec)
        , m_timer(ex)
        , m_on_record(std::move(on_record))
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    // Plain callback overload — used by NativePolicy, MockPolicy, and ASIO adapter users.
    // async_observe() — arms the recv_loop and returns immediately.
    // on_done fires with error_code{} when stop() is called (or empty if omitted).
    // Incoming multicast packets are parsed and each record delivered to the callback.
    // Must only be called once; calling async_observe() twice is a logic error.
    void async_observe(completion_handler on_done = {})
    {
        assert(m_loop == nullptr); // can only start once
        if(on_done)
            m_on_completion = std::move(on_done);
        do_observe();
    }

    // stop() — idempotent; fires the completion handler, then sets the stop flag.
    //
    // Does NOT call m_loop.reset() here — this is critical for callback-safe stop.
    // The recv_loop remains alive until ~basic_observer() destroys it, ensuring that
    // any in-progress callback chain can complete without accessing a dangling loop.
    void stop()
    {
        if(m_stopped.exchange(true, std::memory_order_acq_rel))
            return; // already stopped — idempotent

        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::error_code{});
    }

    // Accessors — basic_observer owns socket and timer directly.
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
            [this](std::span<std::byte> data, const endpoint &sender) -> bool
            {
                on_packet(data, sender);
                return true; // basic_observer wants all traffic; always reset timer
            },
            []()
            {
                /* no-op on silence */
            });

        m_loop->start();
    }

    // Called by recv_loop for every incoming packet.
    // Checks the stop flag, then walks the DNS frame and delivers each record.
    void on_packet(std::span<std::byte> data, const endpoint &sender)
    {
        if(m_stopped.load(std::memory_order_acquire))
            return;

        detail::walk_dns_frame(
            std::span<const std::byte>(data.data(), data.size()),
            sender,
            [this, sender](mdns_record_variant rec)
            {
                if(!m_stopped.load(std::memory_order_acquire) && m_on_record)
                    m_on_record(rec, sender);
            });
    }

    socket_type m_socket;       // socket used for receiving multicast packets
    timer_type m_timer;         // passed to recv_loop for silence-timeout tracking
    record_callback m_on_record; // called once per successfully parsed record
    // Move-only completion handler — called once at stop() or error.
    completion_handler m_on_completion;
    std::unique_ptr<recv_loop<P>> m_loop; // continuous listener (null until async_observe())
    std::atomic<bool> m_stopped;          // idempotent stop flag
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_BASIC_OBSERVER_H

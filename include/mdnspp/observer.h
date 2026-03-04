#ifndef HPP_GUARD_MDNSPP_OBSERVER_H
#define HPP_GUARD_MDNSPP_OBSERVER_H

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/recv_loop.h"
#include "mdnspp/dns_wire.h"

#include <memory>
#include <atomic>
#include <functional>
#include <span>
#include <chrono>
#include <cassert>

namespace mdnspp {

// observer<P> — mDNS multicast listener
//
// Policy-based class template parameterized on:
//   P — Policy: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. observer(ex, callback)        — direct constructor (throwing)
//      observer(ex, callback, ec)    — non-throwing overload (ec set on failure)
//   2. start()                       — arms recv_loop; returns immediately
//   3. stop()                        — idempotent; sets stop flag
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
    using executor_type   = typename P::executor_type;
    using socket_type     = typename P::socket_type;
    using timer_type      = typename P::timer_type;
    using record_callback = std::function<void(mdns_record_variant, endpoint)>;

    // Non-copyable
    observer(const observer &) = delete;
    observer &operator=(const observer &) = delete;

    // Movable only before start() is called (m_loop must be null).
    // Moving a started observer is a logic error (recv_loop callbacks capture this).
    observer(observer &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_timer(std::move(other.m_timer))
        , m_callback(std::move(other.m_callback))
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

    // start() — arms the recv_loop and returns immediately.
    // Incoming multicast packets are parsed and each record delivered to the callback.
    // Must only be called once; calling start() after start() is a logic error.
    void start()
    {
        assert(m_loop == nullptr); // can only start once

        m_loop = std::make_unique<recv_loop<P>>(
            m_socket,
            m_timer,
            std::chrono::hours(24 * 365), // "infinite" silence timeout (run until stop())
            [this](std::span<std::byte> data, endpoint sender) -> bool
            {
                on_packet(data, sender);
                return true; // observer wants all traffic; always reset timer
            },
            []() { /* no-op on silence */ });

        m_loop->start();
    }

    // stop() — idempotent; sets the stop flag.
    //
    // Does NOT call m_loop.reset() here — this is critical for callback-safe stop.
    // The recv_loop remains alive until ~observer() destroys it, ensuring that
    // any in-progress callback chain can complete without accessing a dangling loop.
    void stop()
    {
        if (m_stopped.exchange(true, std::memory_order_acq_rel))
            return; // already stopped — idempotent
    }

    // Accessors — observer owns socket and timer directly.
    const socket_type &socket() const noexcept { return m_socket; }
    socket_type       &socket()       noexcept { return m_socket; }
    const timer_type  &timer()  const noexcept { return m_timer; }
    timer_type        &timer()        noexcept { return m_timer; }

private:
    // Called by recv_loop for every incoming packet.
    // Checks the stop flag, then walks the DNS frame and delivers each record.
    void on_packet(std::span<std::byte> data, endpoint sender)
    {
        if (m_stopped.load(std::memory_order_acquire))
            return;

        detail::walk_dns_frame(
            std::span<const std::byte>(data.data(), data.size()),
            sender,
            [this, sender](mdns_record_variant rec)
            {
                if (!m_stopped.load(std::memory_order_acquire))
                    m_callback(std::move(rec), sender);
            });
    }

    socket_type      m_socket;    // socket used for receiving multicast packets
    timer_type       m_timer;     // passed to recv_loop for silence-timeout tracking
    record_callback  m_callback;  // called once per successfully parsed record
    std::unique_ptr<recv_loop<P>> m_loop; // continuous listener (null until start())
    std::atomic<bool> m_stopped;          // idempotent stop flag
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_OBSERVER_H

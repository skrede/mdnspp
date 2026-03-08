#ifndef HPP_GUARD_MDNSPP_BASIC_OBSERVER_H
#define HPP_GUARD_MDNSPP_BASIC_OBSERVER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <span>
#include <chrono>
#include <cassert>
#include <system_error>

namespace mdnspp {

// basic_observer<P> -- mDNS multicast listener
//
// Policy-based class template parameterized on:
//   P -- Policy: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. basic_observer(ex, opts, on_record)      -- throwing constructor
//      basic_observer(ex, opts, on_record, ec)  -- non-throwing overload (ec set on failure)
//   2. async_observe([on_done])                 -- arms recv_loop; returns immediately
//                                                  on_done fires with error_code{} when stop() is called
//   3. stop()                                   -- idempotent; sets stop flag, fires completion handler
//   4. ~basic_observer()                        -- destroys recv_loop for RAII safety
//
// basic_observer is a pure listener -- no queries sent, no responses built.
// All parsed records are delivered to the callback with the sender endpoint.
// Malformed packets are silently skipped.
//
// stop() is callback-safe: it sets the atomic stop flag but does NOT destroy
// the recv_loop. The recv_loop is cleaned up in ~basic_observer(), which is never
// called from within the recv_loop callback chain.

template <Policy P>
class basic_observer : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;
    using base::timer;

    using record_callback = detail::move_only_function<void(const endpoint &, const mdns_record_variant &)>;

    /// Completion callback fired once when stop() is called.
    /// Receives error_code (always success).
    using completion_handler = detail::move_only_function<void(std::error_code)>;

    /// Error handler invoked on fire-and-forget send failures.
    using error_handler = detail::move_only_function<void(std::error_code, std::string_view)>;

    // Non-copyable, non-move-assignable
    basic_observer(const basic_observer &) = delete;
    basic_observer &operator=(const basic_observer &) = delete;
    basic_observer &operator=(basic_observer &&) = delete;

    // Movable only before async_observe() is called (m_loop must be null).
    // Moving a started basic_observer is a logic error (recv_loop callbacks capture this).
    basic_observer(basic_observer &&other) noexcept
        : base(std::move(other))
        , m_on_record(std::move(other.m_on_record))
        , m_on_completion(std::move(other.m_on_completion))
        , m_on_error(std::move(other.m_on_error))
    {
    }

    ~basic_observer()
    {
        this->m_alive.reset();
        stop();
    }

    // Throwing constructor -- constructs socket and timer from executor.
    // Throws on construction failure (e.g. socket bind error).
    explicit basic_observer(executor_type ex, socket_options opts = {},
                            record_callback on_record = {})
        : base(ex, opts)
        , m_on_record(std::move(on_record))
    {
    }

    // Non-throwing constructor -- sets ec on failure instead of throwing.
    // ec is the last parameter, matching ASIO convention.
    basic_observer(executor_type ex, socket_options opts,
                   record_callback on_record, std::error_code &ec)
        : base(ex, opts, ec)
        , m_on_record(std::move(on_record))
    {
    }

    // Plain callback overload -- used by NativePolicy, MockPolicy, and ASIO adapter users.
    // async_observe() -- arms the recv_loop and returns immediately.
    // on_done fires with error_code{} when stop() is called (or empty if omitted).
    // Incoming multicast packets are parsed and each record delivered to the callback.
    // Must only be called once; calling async_observe() twice is a logic error.
    void async_observe(completion_handler on_done = {})
    {
        assert(this->m_loop == nullptr); // can only start once
        if(on_done)
            m_on_completion = std::move(on_done);
        do_observe();
    }

    /// Sets the error handler invoked on fire-and-forget send failures.
    void on_error(error_handler handler) { m_on_error = std::move(handler); }

    // stop() -- idempotent; posts teardown to executor thread, ensuring all
    // state mutations happen on the executor (no cross-thread data race).
    void stop()
    {
        base::stop([this]()
        {
            if(this->m_loop)
                this->m_loop->stop();

            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::error_code{});
        });
    }

private:
    // Common observe body -- assumes m_on_completion is already set.
    // Creates and starts the recv_loop with "infinite" silence timeout.
    void do_observe()
    {
        this->m_loop = std::make_unique<recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            std::chrono::hours(24 * 365), // "infinite" silence timeout (run until stop())
            [this](const endpoint &sender, std::span<std::byte> data) -> bool
            {
                on_packet(sender, data);
                return true; // basic_observer wants all traffic; always reset timer
            },
            []()
            {
                /* no-op on silence */
            });

        this->m_loop->start();
    }

    // Called by recv_loop for every incoming packet.
    // Checks the stop flag, then walks the DNS frame and delivers each record.
    void on_packet(const endpoint &sender, std::span<std::byte> data)
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return;

        detail::walk_dns_frame(
            std::span<const std::byte>(data.data(), data.size()),
            sender,
            [this, sender](mdns_record_variant rec)
            {
                if(!this->m_stopped.load(std::memory_order_acquire) && m_on_record)
                    m_on_record(sender, rec);
            });
    }

    record_callback m_on_record;
    completion_handler m_on_completion;
    error_handler m_on_error;
};

}

#endif

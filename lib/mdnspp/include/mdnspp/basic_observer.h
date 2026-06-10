#ifndef HPP_GUARD_MDNSPP_BASIC_OBSERVER_H
#define HPP_GUARD_MDNSPP_BASIC_OBSERVER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/callback_types.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"

#include <span>
#include <chrono>
#include <utility>
#include <system_error>

namespace mdnspp {

// basic_observer<P> -- mDNS multicast listener
//
// Policy-based class template parameterized on:
//   P -- policy_like: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. basic_observer(ex, opts)      -- throwing constructor
//      basic_observer(ex, opts, ec)  -- non-throwing overload (ec set on failure)
//   2. async_observe([on_done])      -- arms recv_loop; returns immediately
//   3. stop()                        -- idempotent; completes on_done with
//                                       std::errc::operation_canceled
//   4. ~basic_observer()             -- completes a still-pending on_done with
//                                       operation_canceled, then destroys the
//                                       recv_loop for RAII safety
//
// basic_observer is a pure packet listener -- no queries sent, no responses
// built. ALL parsed records are delivered to the callback with the sender
// endpoint, including records carried in query packets (known-answer lists,
// probe proposals): the observer performs no QR-flag or section filtering.
// Malformed packets are silently skipped.
//
// Completion semantics:
//   - The observation has no natural completion; on_done fires only via stop()
//     or destruction, with std::errc::operation_canceled.
//   - A second async_observe() (or a call after stop()) completes the supplied
//     handler with operation_in_progress / invalid_argument.
//
// stop() is callback-safe: it sets the atomic stop flag but does NOT destroy
// the recv_loop. The recv_loop is cleaned up in ~basic_observer(), which is never
// called from within the recv_loop callback chain.

template <policy_like P>
class basic_observer : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;
    using base::timer;

    using record_callback = mdnspp::record_callback;

    /// Completion callback fired once when the observation ends (stop() or
    /// destruction): std::errc::operation_canceled.
    using completion_handler = mdnspp::observer_completion_handler;

    /// Error handler invoked on fatal receive errors.
    using error_handler = mdnspp::error_handler;

    // Non-copyable and non-movable (recv_loop handlers capture this)
    basic_observer(const basic_observer &) = delete;
    basic_observer &operator=(const basic_observer &) = delete;
    basic_observer(basic_observer &&) = delete;
    basic_observer &operator=(basic_observer &&) = delete;

    ~basic_observer()
    {
        this->m_alive.reset();
        stop();
        // The posted stop() teardown is dropped by the expired alive guard;
        // complete a still-pending handler instead of silently dropping it.
        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::make_error_code(std::errc::operation_canceled));
    }

    // Throwing constructor -- constructs socket and timer from executor.
    // Throws on construction failure (e.g. socket bind error) and on invalid
    // mdns_options (std::errc::invalid_argument).
    explicit basic_observer(executor_type ex, observer_options opts = {},
                            policy_socket_options_t<P> sock_opts = {},
                            mdns_options mdns_opts = {})
        : base(ex, std::move(sock_opts), std::move(mdns_opts))
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        detail::throw_on_error(detail::validate_mdns_options(this->m_mdns_opts));
    }

    // Non-throwing constructor -- sets ec on failure instead of throwing.
    // ec is the last parameter, matching ASIO convention.
    basic_observer(executor_type ex, observer_options opts,
                   policy_socket_options_t<P> sock_opts, mdns_options mdns_opts,
                   std::error_code &ec)
        : base(ex, std::move(sock_opts), std::move(mdns_opts), ec)
        , m_on_error(std::move(opts.on_error))
        , m_on_record(std::move(opts.on_record))
    {
        if(!ec)
            ec = detail::validate_mdns_options(this->m_mdns_opts);
    }

    // Plain callback overload -- used by default_policy, mock_policy, and ASIO adapter users.
    // async_observe() -- arms the recv_loop and returns immediately.
    // on_done fires with operation_canceled when the observation ends.
    // Incoming multicast packets are parsed and each record delivered to the callback.
    //
    // One-shot: a second call (or a call after stop()) completes on_done with
    // operation_in_progress / invalid_argument without touching the running
    // observation.
    void async_observe(completion_handler on_done = {})
    {
        if(auto misuse = check_start_misuse())
        {
            if(on_done)
                this->post_guarded([h = std::move(on_done), misuse]() mutable
                {
                    h(misuse);
                });
            return;
        }
        if(on_done)
            m_on_completion = std::move(on_done);
        do_observe();
    }

    // stop() -- idempotent; posts teardown to executor thread, ensuring all
    // state mutations happen on the executor (no cross-thread data race).
    // The completion handler fires with operation_canceled.
    void stop()
    {
        base::stop([this]()
        {
            if(this->m_loop)
                this->m_loop->stop();

            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::make_error_code(std::errc::operation_canceled));
        });
    }

private:
    // Detects one-shot misuse: a second start or reuse after stop().
    [[nodiscard]] std::error_code check_start_misuse() const noexcept
    {
        if(this->m_loop)
            return std::make_error_code(std::errc::operation_in_progress);
        if(this->m_stopped.load(std::memory_order_acquire))
            return std::make_error_code(std::errc::invalid_argument);
        return {};
    }

    // Common observe body -- assumes m_on_completion is already set.
    // Creates and starts the recv_loop with an "infinite" silence timeout.
    void do_observe()
    {
        this->m_loop = std::make_unique<detail::recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            detail::infinite_silence_timeout, // run until stop()
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                on_packet(meta.sender, data);
                return true; // basic_observer wants all traffic; always reset timer
            },
            []()
            {
                /* no-op on silence */
            },
            this->m_mdns_opts.receive_ttl_minimum,
            this->m_mdns_opts.unknown_ttl_policy,
            [this](std::error_code ec)
            {
                if(m_on_error)
                    m_on_error(ec, "receive");
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

    error_handler m_on_error;
    record_callback m_on_record;
    completion_handler m_on_completion;
};

}

#endif

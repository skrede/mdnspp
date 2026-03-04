#ifndef HPP_GUARD_MDNSPP_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_SERVICE_SERVER_H

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/recv_loop.h"
#include "mdnspp/dns_wire.h"

#include <algorithm>
#include <memory>
#include <random>
#include <chrono>
#include <atomic>
#include <span>
#include <cstdint>
#include <functional>
#include <cassert>
#include <system_error>
#include <utility>

#ifdef ASIO_STANDALONE
#include <asio/async_result.hpp>
#include <asio/detached.hpp>
#include <asio/dispatch.hpp>
#include <asio/executor_work_guard.hpp>
#include <asio/bind_allocator.hpp>
#include <asio/recycling_allocator.hpp>
#include <asio/associated_allocator.hpp>
#endif

namespace mdnspp {

// service_server<P> — mDNS service responder
//
// Policy-based class template parameterized on:
//   P — Policy: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. service_server(ex, info)          — direct constructor (throwing)
//      service_server(ex, info, ec)      — non-throwing overload (ec set on failure)
//   2. async_start([on_done])            — arms recv_loop; returns immediately
//                                          on_done fires with error_code{} when stop() is called
//   3. stop()                            — idempotent; fires completion handler, cancels timer,
//                                          destroys loop
//   4. ~service_server()                 — calls stop() for RAII safety
//
// No inheritance. No std::mutex. BEHAV-03 compliant.
// Response delay 20-500ms per RFC 6762 section 6 (BEHAV-04).

template <Policy P>
class service_server
{
public:
    using executor_type  = typename P::executor_type;
    using socket_type    = typename P::socket_type;
    using timer_type     = typename P::timer_type;

    /// Optional callback invoked when an incoming query is received and parsed.
    /// Parameters: sender endpoint, qtype requested, whether unicast was requested.
    using query_callback = std::function<void(endpoint, uint16_t, bool)>;

    /// Completion callback fired once when stop() is called.
    /// Receives error_code (always success).
    using completion_handler = std::function<void(std::error_code)>;

    // Non-copyable
    service_server(const service_server &) = delete;
    service_server &operator=(const service_server &) = delete;

    // Movable only before async_start() is called (m_loop must be null).
    // Moving a started server is a logic error.
    service_server(service_server &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_response_timer(std::move(other.m_response_timer))
        , m_recv_timer(std::move(other.m_recv_timer))
        , m_info(std::move(other.m_info))
        , m_on_query(std::move(other.m_on_query))
        , m_on_completion(std::move(other.m_on_completion))
        , m_rng(std::move(other.m_rng))
        , m_loop(std::move(other.m_loop))
        , m_stopped(other.m_stopped.load(std::memory_order_acquire))
    {
        // Source must not have been started — loop must be null
        assert(other.m_loop == nullptr);
        other.m_stopped.store(true, std::memory_order_release);
    }

    service_server &operator=(service_server &&other) noexcept
    {
        if (this == &other)
            return *this;
        assert(m_loop == nullptr);       // this server must not be started
        assert(other.m_loop == nullptr); // source must not be started
        m_socket         = std::move(other.m_socket);
        m_response_timer = std::move(other.m_response_timer);
        m_recv_timer     = std::move(other.m_recv_timer);
        m_info           = std::move(other.m_info);
        m_on_query       = std::move(other.m_on_query);
        m_on_completion  = std::move(other.m_on_completion);
        m_rng            = std::move(other.m_rng);
        m_loop           = std::move(other.m_loop);
        m_stopped.store(other.m_stopped.load(std::memory_order_acquire),
                        std::memory_order_release);
        other.m_stopped.store(true, std::memory_order_release);
        return *this;
    }

    ~service_server()
    {
        stop();
    }

    // Throwing constructor — constructs socket and both timers from executor.
    explicit service_server(executor_type ex, service_info info,
                            query_callback on_query = {})
        : m_socket(ex)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_on_query(std::move(on_query))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    // Non-throwing constructors — ec is last (ASIO convention).
    service_server(executor_type ex, service_info info,
                   query_callback on_query, std::error_code &ec)
        : m_socket(ex, ec)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_on_query(std::move(on_query))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    service_server(executor_type ex, service_info info, std::error_code &ec)
        : m_socket(ex, ec)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

#ifndef ASIO_STANDALONE
    // Non-template callback overload — used by NativePolicy and MockPolicy users.
    // async_start() — arms the recv_loop and returns immediately.
    // on_done fires with error_code{} when stop() is called (or empty if omitted).
    // Incoming queries trigger RFC 6762-delayed responses.
    // Must only be called once; calling async_start() twice is a logic error.
    void async_start(completion_handler on_done = {})
    {
        assert(m_loop == nullptr); // can only start once
        m_on_completion = std::move(on_done);
        do_start();
    }
#endif

#ifdef ASIO_STANDALONE
    /// Zero-argument fire-and-forget overload for ASIO users — equivalent to async_start(asio::detached).
    void async_start()
    {
        async_start(asio::detached);
    }

    /// ASIO completion token overload — accepts use_future, use_awaitable, deferred, or any callable.
    /// Fires when stop() is called with signature void(std::error_code).
    /// NativePolicy users (no ASIO_STANDALONE) use the non-template overload above instead.
    template <asio::completion_token_for<void(std::error_code)> CompletionToken>
    auto async_start(CompletionToken&& token)
    {
        return asio::async_initiate<CompletionToken, void(std::error_code)>(
            [this](auto handler)
            {
                auto work = asio::make_work_guard(handler);

                // Type-erase into completion_handler, dispatching via the handler's executor.
                m_on_completion = [h = std::move(handler), w = std::move(work)](
                    std::error_code ec) mutable
                {
                    auto alloc = asio::get_associated_allocator(
                        h, asio::recycling_allocator<void>());
                    asio::dispatch(w.get_executor(),
                        asio::bind_allocator(alloc,
                            [h2 = std::move(h), ec]() mutable
                            {
                                std::move(h2)(ec);
                            }));
                };

                do_start();
            },
            token);
    }
#endif

    // stop() — idempotent; fires the completion handler, cancels response timer,
    // destroys recv_loop.
    // The completion handler fires BEFORE canceling the timer and destroying the loop,
    // so the handler can safely access server state.
    void stop()
    {
        if (m_stopped.exchange(true, std::memory_order_acq_rel))
            return; // already stopped

        if (auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::error_code{});

        m_response_timer.cancel();
        m_loop.reset(); // destructor calls stop() on the loop
    }

    // Accessors — service_server owns socket and timers directly.
    const socket_type &socket()      const noexcept { return m_socket; }
    socket_type       &socket()            noexcept { return m_socket; }
    const timer_type  &timer()       const noexcept { return m_response_timer; }
    timer_type        &timer()             noexcept { return m_response_timer; }
    const timer_type  &recv_timer()  const noexcept { return m_recv_timer; }
    timer_type        &recv_timer()        noexcept { return m_recv_timer; }

private:
    // Common start body — assumes m_on_completion is already set.
    // Creates and starts the recv_loop with "infinite" silence timeout.
    void do_start()
    {
        m_loop = std::make_unique<recv_loop<P>>(
            m_socket,
            m_recv_timer,
            std::chrono::hours(24 * 365), // "infinite" silence timeout (run until stop())
            [this](std::span<std::byte> data, endpoint sender) -> bool
            {
                on_query(data, sender);
                return true; // server needs to see all queries; always reset timer
            },
            []() { /* no-op on silence */ });

        m_loop->start();
    }

    // Returns true if the wire-encoded DNS name at data[12..name_end) matches
    // any name this server is authoritative for.
    bool query_matches(std::span<const std::byte> data, size_t name_end) const
    {
        auto qname = data.subspan(12, name_end - 12);
        auto match = [&](std::string_view name) {
            auto encoded = detail::encode_dns_name(name);
            return std::ranges::equal(qname, std::span<const std::byte>(encoded));
        };
        return match(m_info.service_type)
            || match(m_info.service_name)
            || match(m_info.hostname);
    }

    // Called by recv_loop on every incoming packet.
    void on_query(std::span<std::byte> data, endpoint sender)
    {
        if (m_stopped.load(std::memory_order_acquire))
            return;

        // Parse QTYPE from the DNS query:
        //   Bytes 0-11: DNS header
        //   Byte 4-5:   qdcount
        //   Byte 12+:   question section — name (variable), then qtype(2), qclass(2)
        if (data.size() < 12)
            return;

        const std::byte *buf = data.data();

        // Extract qdcount (offset 4, big-endian 2 bytes)
        uint16_t qdcount = detail::read_u16_be(buf + 4);
        if (qdcount == 0)
            return;

        // Skip past question name to reach QTYPE
        size_t offset = 12;
        if (!detail::skip_dns_name(
                std::span<const std::byte>(data.data(), data.size()), offset))
            return;

        // Need 4 bytes for QTYPE(2) + QCLASS(2)
        if (offset + 4 > data.size())
            return;

        // Only respond to queries that match our service/hostname
        if (!query_matches(data, offset))
            return;

        uint16_t qtype  = detail::read_u16_be(buf + offset);
        uint16_t qclass = detail::read_u16_be(buf + offset + 2);

        // RFC 6762 section 5.4: QU bit is the top bit of QCLASS.
        // If set, the querier requests a unicast response directly to its address.
        // Otherwise, respond via multicast so all listeners benefit.
        bool unicast_response = (qclass & 0x8000) != 0;

        if (m_on_query)
            m_on_query(sender, qtype, unicast_response);

        // RFC 6762 section 6: random delay 20-500ms before responding via multicast.
        // Unicast responses may be sent immediately, but we apply the delay uniformly.
        std::uniform_int_distribution<int> dist(20, 500);
        int delay_ms = dist(m_rng);

        // Choose destination: unicast back to querier, or multicast to the group
        endpoint dest = unicast_response
            ? sender
            : endpoint{"224.0.0.251", 5353};

        // Arm response timer with delay; capture dest and qtype by value
        m_response_timer.expires_after(std::chrono::milliseconds(delay_ms));
        m_response_timer.async_wait(
            [this, dest, qtype](std::error_code ec)
            {
                if (ec || m_stopped.load(std::memory_order_acquire))
                    return;
                send_response(dest, qtype);
            });
    }

    // Builds and sends a DNS response to dest for the given qtype.
    // dest is either the multicast group (default) or the querier's unicast address
    // (when QU bit was set in the question). Uses m_socket directly — service_server
    // owns the socket, not recv_loop.
    void send_response(endpoint dest, uint16_t qtype)
    {
        auto response = detail::build_dns_response(m_info, qtype);
        if (response.empty())
            return; // unmatched qtype or missing address

        m_socket.send(dest, std::span<const std::byte>(response));
    }

    socket_type    m_socket;           // socket used for sending responses
    timer_type     m_response_timer;   // RFC 6762 response delay timer
    timer_type     m_recv_timer;       // passed to recv_loop for silence tracking
    service_info   m_info;             // service description for DNS responses
    query_callback m_on_query;         // optional per-query callback
    completion_handler m_on_completion; // fires once when stop() is called
    std::mt19937   m_rng;              // PRNG for random delay generation
    std::unique_ptr<recv_loop<P>> m_loop; // continuous query listener (null until async_start())
    std::atomic<bool> m_stopped;          // idempotent stop flag
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_SERVICE_SERVER_H

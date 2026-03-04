#ifndef HPP_GUARD_MDNSPP_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_SERVICE_SERVER_H

#include "mdnspp/socket_policy.h"
#include "mdnspp/timer_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/recv_loop.h"
#include "mdnspp/dns_wire.h"

#include <expected>
#include <memory>
#include <random>
#include <chrono>
#include <atomic>
#include <span>
#include <cstdint>
#include <functional>
#include <cassert>

namespace mdnspp {

// service_server<S, T> — mDNS service responder
//
// Policy-based class template parameterized on:
//   S — SocketPolicy: provides async_receive(), send(), close()
//   T — TimerPolicy:  provides expires_after(), async_wait(), cancel()
//
// Lifecycle:
//   1. create(socket, timer, info) — factory; returns std::expected
//   2. start()                     — arms recv_loop; returns immediately
//   3. stop()                      — idempotent; cancels timer, destroys loop
//   4. ~service_server()           — calls stop() for RAII safety
//
// No mdns_base inheritance. No std::mutex. BEHAV-03 compliant.
// Response delay 20-500ms per RFC 6762 section 6 (BEHAV-04).

template <SocketPolicy S, TimerPolicy T>
class service_server
{
public:
    // Non-copyable
    service_server(const service_server &) = delete;
    service_server &operator=(const service_server &) = delete;

    // Movable only before start() is called (m_loop must be null).
    // Moving a started server is a logic error.
    service_server(service_server &&other) noexcept
        : m_socket(std::move(other.m_socket))
        , m_response_timer(std::move(other.m_response_timer))
        , m_recv_timer(std::move(other.m_recv_timer))
        , m_info(std::move(other.m_info))
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
        assert(m_loop == nullptr);   // this server must not be started
        assert(other.m_loop == nullptr); // source must not be started
        m_socket         = std::move(other.m_socket);
        m_response_timer = std::move(other.m_response_timer);
        m_recv_timer     = std::move(other.m_recv_timer);
        m_info           = std::move(other.m_info);
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

    // Factory — creates a service_server or returns an mdns_error.
    //
    // Takes two separate timer instances:
    //   response_timer — used for RFC 6762 20-500ms response delay
    //   recv_timer     — passed to recv_loop for silence-timeout tracking
    //
    // Two separate timers are required because T (e.g. AsioTimerPolicy) may wrap a
    // non-copyable type (asio::steady_timer). Requiring the caller to provide two
    // distinct timer instances avoids implicit copying and is explicit about ownership.
    [[nodiscard]] static std::expected<service_server, mdns_error>
    create(S socket, T response_timer, T recv_timer, service_info info)
    {
        return service_server(std::move(socket), std::move(response_timer),
                              std::move(recv_timer), std::move(info));
    }

    // start() — arms the recv_loop and returns immediately.
    // Incoming queries trigger RFC 6762-delayed responses.
    // Must only be called once; calling start() after start() is a logic error.
    //
    // m_socket and m_recv_timer are moved into the recv_loop on start().
    // After start(), all socket access (including send_response) goes through
    // m_loop->socket() — this supports non-copyable policies like AsioSocketPolicy.
    void start()
    {
        assert(m_loop == nullptr); // can only start once

        m_loop = std::make_unique<recv_loop<S, T>>(
            std::move(m_socket),     // move — recv_loop owns the socket; we access via m_loop->socket()
            std::move(m_recv_timer), // move — recv_loop owns the recv timer
            std::chrono::hours(24 * 365), // "infinite" silence timeout (run until stop())
            [this](std::span<std::byte> data, endpoint sender)
            {
                on_query(data, sender);
            },
            []() { /* no-op on silence */ });

        m_loop->start();
    }

    // stop() — idempotent; cancels response timer, destroys recv_loop.
    void stop()
    {
        if (m_stopped.exchange(true, std::memory_order_acq_rel))
            return; // already stopped

        m_response_timer.cancel();
        m_loop.reset(); // destructor calls stop() on the loop
    }

    // Test accessors — allow tests to inspect internal socket/timer state.
    // After start(), m_socket has been moved into m_loop; socket() returns the loop's copy.
    // Before start(), returns m_socket directly (for pre-start inspection).
    const S &socket() const noexcept
    {
        return m_loop ? m_loop->socket() : m_socket;
    }
    S &socket() noexcept
    {
        return m_loop ? m_loop->socket() : m_socket;
    }
    const T &timer() const noexcept  { return m_response_timer; }
    T       &timer()       noexcept  { return m_response_timer; }

private:
    explicit service_server(S socket, T response_timer, T recv_timer, service_info info)
        : m_socket(std::move(socket))
        , m_response_timer(std::move(response_timer))
        , m_recv_timer(std::move(recv_timer))
        , m_info(std::move(info))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
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

        // Need 2 bytes for QTYPE
        if (offset + 2 > data.size())
            return;

        uint16_t qtype = detail::read_u16_be(buf + offset);

        // Generate random delay in [20, 500] ms — RFC 6762 section 6
        std::uniform_int_distribution<int> dist(20, 500);
        int delay_ms = dist(m_rng);

        // Arm response timer with delay; capture sender and qtype by value
        m_response_timer.expires_after(std::chrono::milliseconds(delay_ms));
        m_response_timer.async_wait(
            [this, sender, qtype](std::error_code ec)
            {
                if (ec || m_stopped.load(std::memory_order_acquire))
                    return;
                send_response(sender, qtype);
            });
    }

    // Builds and sends a DNS response to dest for the given qtype.
    // Uses m_loop->socket() because m_socket was moved into the recv_loop on start().
    void send_response(endpoint dest, uint16_t qtype)
    {
        auto response = detail::build_dns_response(m_info, qtype);
        if (response.empty())
            return; // unmatched qtype or missing address

        if (m_loop)
            m_loop->socket().send(dest, std::span<const std::byte>(response));
    }

    S          m_socket;           // socket used for sending responses
    T          m_response_timer;   // RFC 6762 response delay timer
    T          m_recv_timer;       // passed to recv_loop for silence tracking
    service_info m_info;           // service description for DNS responses
    std::mt19937 m_rng;            // PRNG for random delay generation
    std::unique_ptr<recv_loop<S, T>> m_loop; // continuous query listener (null until start())
    std::atomic<bool> m_stopped;   // idempotent stop flag
};

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_SERVICE_SERVER_H

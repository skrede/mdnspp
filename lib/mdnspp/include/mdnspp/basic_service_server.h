#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/recv_loop.h"

#include <algorithm>
#include <memory>
#include <random>
#include <chrono>
#include <atomic>
#include <span>
#include <cstdint>
#include <cassert>
#include <system_error>
#include <utility>

namespace mdnspp {

// basic_service_server<P> -- mDNS service responder
//
// Policy-based class template parameterized on:
//   P -- Policy: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. Construct with (ex, info, opts) or (ex, sock_opts, info, opts)
//   2. async_start(on_ready, on_done) -- begins probe -> announce -> live sequence
//      on_ready fires with error_code{} when live, or probe_conflict on conflict
//      on_done fires with error_code{} when stop() is called
//   3. stop() -- idempotent; cancels probing/announcing, fires on_ready with
//      operation_canceled if not yet live, then fires on_done
//   4. ~basic_service_server() -- calls stop() for RAII safety

template <Policy P>
class basic_service_server
{
public:
    using executor_type = typename P::executor_type;
    using socket_type = typename P::socket_type;
    using timer_type = typename P::timer_type;

    /// Optional callback invoked when an incoming query is received and parsed.
    /// Parameters: sender endpoint, qtype requested, response mode (unicast or multicast).
    using query_callback = detail::move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)>;

    /// Completion callback fired once when stop() is called or on_ready event occurs.
    /// Receives error_code.
    using completion_handler = detail::move_only_function<void(std::error_code)>;

    // Non-copyable
    basic_service_server(const basic_service_server &) = delete;
    basic_service_server &operator=(const basic_service_server &) = delete;

    // Movable only before async_start() is called (m_loop must be null).
    // Moving a started server is a logic error.
    basic_service_server(basic_service_server &&other) noexcept
        : m_alive(std::move(other.m_alive))
        , m_executor(other.m_executor)
        , m_socket(std::move(other.m_socket))
        , m_response_timer(std::move(other.m_response_timer))
        , m_recv_timer(std::move(other.m_recv_timer))
        , m_info(std::move(other.m_info))
        , m_opts(std::move(other.m_opts))
        , m_on_ready(std::move(other.m_on_ready))
        , m_on_completion(std::move(other.m_on_completion))
        , m_rng(std::move(other.m_rng))
        , m_loop(std::move(other.m_loop))
        , m_state(other.m_state)
        , m_probe_count(other.m_probe_count)
        , m_announce_count(other.m_announce_count)
        , m_conflict_attempt(other.m_conflict_attempt)
        , m_stopped(other.m_stopped.load(std::memory_order_acquire))
    {
        // Source must not have been started -- loop must be null
        assert(other.m_loop == nullptr);
        other.m_stopped.store(true, std::memory_order_release);
    }

    basic_service_server &operator=(basic_service_server &&other) noexcept
    {
        if(this == &other)
            return *this;
        assert(m_loop == nullptr);       // this server must not be started
        assert(other.m_loop == nullptr); // source must not be started
        m_alive = std::move(other.m_alive);
        m_executor = other.m_executor;
        m_socket = std::move(other.m_socket);
        m_response_timer = std::move(other.m_response_timer);
        m_recv_timer = std::move(other.m_recv_timer);
        m_info = std::move(other.m_info);
        m_opts = std::move(other.m_opts);
        m_on_ready = std::move(other.m_on_ready);
        m_on_completion = std::move(other.m_on_completion);
        m_rng = std::move(other.m_rng);
        m_loop = std::move(other.m_loop);
        m_state = other.m_state;
        m_probe_count = other.m_probe_count;
        m_announce_count = other.m_announce_count;
        m_conflict_attempt = other.m_conflict_attempt;
        m_stopped.store(other.m_stopped.load(std::memory_order_acquire),
                        std::memory_order_release);
        other.m_stopped.store(true, std::memory_order_release);
        return *this;
    }

    ~basic_service_server()
    {
        m_alive.reset(); // invalidate sentinel first
        stop();          // then stop (discards pending work via event loop)
    }

    // Throwing constructors
    explicit basic_service_server(executor_type ex, service_info info,
                                  service_options opts = {})
        : m_executor(ex)
        , m_socket(ex)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    explicit basic_service_server(executor_type ex, const socket_options &sock_opts,
                                  service_info info, service_options opts = {})
        : m_executor(ex)
        , m_socket(ex, sock_opts)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    // Non-throwing constructors
    basic_service_server(executor_type ex, service_info info, std::error_code &ec)
        : m_executor(ex)
        , m_socket(ex, ec)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    basic_service_server(executor_type ex, service_info info,
                         service_options opts, std::error_code &ec)
        : m_executor(ex)
        , m_socket(ex, ec)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    basic_service_server(executor_type ex, const socket_options &sock_opts,
                         service_info info, std::error_code &ec)
        : m_executor(ex)
        , m_socket(ex, sock_opts, ec)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    basic_service_server(executor_type ex, const socket_options &sock_opts,
                         service_info info, service_options opts,
                         std::error_code &ec)
        : m_executor(ex)
        , m_socket(ex, sock_opts, ec)
        , m_response_timer(ex)
        , m_recv_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
        , m_loop(nullptr)
        , m_stopped(false)
    {
    }

    // async_start() -- begins the probe -> announce -> live sequence.
    // on_ready fires after probe+announce completes (success) or on conflict.
    // on_done fires when stop() is called.
    // Must only be called once; calling async_start() twice is a logic error.
    void async_start(completion_handler on_ready = {}, completion_handler on_done = {})
    {
        assert(m_state == server_state::idle);
        if(on_ready)
            m_on_ready = std::move(on_ready);
        if(on_done)
            m_on_completion = std::move(on_done);
        do_start();
    }

    // stop() -- idempotent; fires on_ready with operation_canceled if still probing/announcing,
    // then fires on_done, cancels timer, destroys recv_loop.
    void stop()
    {
        if(m_stopped.exchange(true, std::memory_order_acq_rel))
            return; // already stopped

        if(m_state == server_state::probing || m_state == server_state::announcing)
        {
            if(auto h = std::exchange(m_on_ready, nullptr); h)
                h(std::make_error_code(std::errc::operation_canceled));
        }

        m_state = server_state::stopped;

        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::error_code{});

        m_response_timer.cancel();
        m_loop.reset();
    }

    // update_service_info() -- posts a service info replacement to the event loop.
    // After the update executes, an announcement burst is sent with announce_count
    // announcements at announce_interval intervals per RFC 6762 section 8.4.
    // Must only be called on a running server (after async_start(), before stop()).
    // Thread-safe: may be called from any thread.
    void update_service_info(service_info new_info)
    {
        assert(!m_stopped.load(std::memory_order_acquire)); // must be running
        auto guard = std::weak_ptr<bool>(m_alive);
        P::post(m_executor, [this, guard, info = std::move(new_info)]() mutable
        {
            if(!guard.lock()) return;
            if(m_stopped.load(std::memory_order_acquire)) return;
            m_info = std::move(info);
            m_announce_count = 0;
            send_update_announce();
        });
    }

    const socket_type &socket() const noexcept { return m_socket; }
    socket_type &socket() noexcept { return m_socket; }
    const timer_type &timer() const noexcept { return m_response_timer; }
    timer_type &timer() noexcept { return m_response_timer; }
    const timer_type &recv_timer() const noexcept { return m_recv_timer; }
    timer_type &recv_timer() noexcept { return m_recv_timer; }

private:
    enum class server_state : uint8_t { idle, probing, announcing, live, stopped };

    // Common start body -- creates recv_loop and begins probing.
    void do_start()
    {
        m_loop = std::make_unique<recv_loop<P>>(
            m_socket,
            m_recv_timer,
            std::chrono::hours(24 * 365), // "infinite" silence timeout (run until stop())
            [this](const endpoint &sender, std::span<std::byte> data) -> bool
            {
                on_query(sender, data);
                return true;
            },
            []()
            {
                // no-op on silence
            });

        start_probing();
        m_loop->start();
    }

    // Begins the probing sequence: random delay 0-250ms, then 3 probes at 250ms intervals.
    void start_probing()
    {
        m_state = server_state::probing;
        m_probe_count = 0;

        // Random delay 0-250ms before first probe (RFC 6762 section 8.1)
        std::uniform_int_distribution dist(0, 250);
        m_response_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_state != server_state::probing) return;
            if(m_stopped.load(std::memory_order_acquire)) return;
            send_probe();
        });
    }

    // Sends a single probe query and schedules the next.
    void send_probe()
    {
        if(m_state != server_state::probing) return;
        if(m_stopped.load(std::memory_order_acquire)) return;

        auto probe = detail::build_probe_query(m_info);
        m_socket.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(probe));
        ++m_probe_count;

        if(m_probe_count < 3)
        {
            // Schedule next probe at 250ms
            m_response_timer.expires_after(std::chrono::milliseconds(250));
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || m_state != server_state::probing) return;
                if(m_stopped.load(std::memory_order_acquire)) return;
                send_probe();
            });
        }
        else
        {
            // Wait 250ms after last probe for conflicts, then start announcing
            m_response_timer.expires_after(std::chrono::milliseconds(250));
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || m_state != server_state::probing) return;
                if(m_stopped.load(std::memory_order_acquire)) return;
                start_announcing();
            });
        }
    }

    // Begins the announcement burst after successful probing.
    void start_announcing()
    {
        m_state = server_state::announcing;
        m_announce_count = 0;
        send_announce();
    }

    // Sends one announcement and schedules the next if needed.
    void send_announce()
    {
        if(m_state != server_state::announcing) return;
        if(m_stopped.load(std::memory_order_acquire)) return;

        send_announcement();
        ++m_announce_count;

        if(m_announce_count < m_opts.announce_count)
        {
            m_response_timer.expires_after(m_opts.announce_interval);
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || m_state != server_state::announcing) return;
                if(m_stopped.load(std::memory_order_acquire)) return;
                send_announce();
            });
        }
        else
        {
            // Probe+announce complete -- server is live
            m_state = server_state::live;
            if(auto h = std::exchange(m_on_ready, nullptr); h)
                h(std::error_code{});
        }
    }

    // Handles conflict detected during probing.
    void handle_conflict()
    {
        m_response_timer.cancel();

        if(m_opts.on_conflict)
        {
            std::string new_name;
            if(m_opts.on_conflict(m_info.service_name, new_name, m_conflict_attempt))
            {
                m_info.service_name = std::move(new_name);
                ++m_conflict_attempt;
                start_probing();
                return;
            }
        }

        // No callback or callback returned false -- fail
        m_state = server_state::stopped;
        m_stopped.store(true, std::memory_order_release);
        if(auto h = std::exchange(m_on_ready, nullptr); h)
            h(mdns_error::probe_conflict);
    }

    // Sends update announcements as a burst (for update_service_info).
    void send_update_announce()
    {
        if(m_stopped.load(std::memory_order_acquire)) return;
        if(m_state != server_state::live) return;

        send_announcement();
        ++m_announce_count;

        if(m_announce_count < m_opts.announce_count)
        {
            m_response_timer.expires_after(m_opts.announce_interval);
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || m_stopped.load(std::memory_order_acquire)) return;
                if(m_state != server_state::live) return;
                send_update_announce();
            });
        }
    }

    // Returns true if the wire-encoded DNS name at data[12..name_end) matches
    // any name this server is authoritative for.
    bool query_matches(std::span<const std::byte> data, size_t name_end) const
    {
        auto qname = data.subspan(12, name_end - 12);
        auto match = [&](std::string_view name)
        {
            auto encoded = detail::encode_dns_name(name);
            return std::ranges::equal(qname, std::span<const std::byte>(encoded));
        };
        return match(m_info.service_type)
            || match(m_info.service_name)
            || match(m_info.hostname);
    }

    // Checks if an incoming DNS response contains records matching our probed names.
    bool response_conflicts(std::span<std::byte> data) const
    {
        bool conflict = false;
        detail::walk_dns_frame(std::span<const std::byte>(data.data(), data.size()),
            endpoint{}, [&](mdns_record_variant rv)
        {
            auto check_name = [&](std::string_view record_name)
            {
                // Strip trailing dot from record_name for comparison if needed.
                // service_name etc. have trailing dots. walk_dns_frame produces names without trailing dot.
                auto strip_dot = [](std::string_view s) -> std::string_view
                {
                    if(!s.empty() && s.back() == '.')
                        return s.substr(0, s.size() - 1);
                    return s;
                };
                auto sn = strip_dot(m_info.service_name);
                auto hn = strip_dot(m_info.hostname);
                if(record_name == sn || record_name == hn)
                    conflict = true;
            };

            std::visit([&](const auto &rec)
            {
                check_name(rec.name);
            }, rv);
        });
        return conflict;
    }

    // Called by recv_loop on every incoming packet.
    void on_query(const endpoint &sender, std::span<std::byte> data)
    {
        if(m_stopped.load(std::memory_order_acquire))
            return;

        // During probing: check for conflicting responses, drop everything
        if(m_state == server_state::probing)
        {
            if(data.size() >= 12)
            {
                uint16_t flags = detail::read_u16_be(data.data() + 2);
                if(flags & 0x8000) // QR=1, this is a response
                {
                    if(response_conflicts(data))
                        handle_conflict();
                }
            }
            return;
        }

        // Drop queries during announcing
        if(m_state != server_state::live)
            return;

        // Parse QTYPE from the DNS query:
        //   Bytes 0-11: DNS header
        //   Byte 4-5:   qdcount
        //   Byte 12+:   question section -- name (variable), then qtype(2), qclass(2)
        if(data.size() < 12)
            return;

        const std::byte *buf = data.data();

        // Extract qdcount (offset 4, big-endian 2 bytes)
        uint16_t qdcount = detail::read_u16_be(buf + 4);
        if(qdcount == 0)
            return;

        // Skip past question name to reach QTYPE
        size_t offset = 12;
        if(!detail::skip_dns_name(
            std::span<const std::byte>(data.data(), data.size()), offset))
            return;

        // Need 4 bytes for QTYPE(2) + QCLASS(2)
        if(offset + 4 > data.size())
            return;

        // Only respond to queries that match our service/hostname
        if(!query_matches(data, offset))
            return;

        dns_type qtype = static_cast<dns_type>(detail::read_u16_be(buf + offset));
        uint16_t qclass = detail::read_u16_be(buf + offset + 2);

        // RFC 6762 section 5.4: QU bit is the top bit of QCLASS.
        auto resp_mode = (qclass & 0x8000) != 0
                             ? response_mode::unicast
                             : response_mode::multicast;

        if(m_opts.on_query)
            m_opts.on_query(sender, qtype, resp_mode);

        // RFC 6762 section 6: random delay 20-500ms before responding via multicast.
        // Unicast responses may be sent immediately.
        std::uniform_int_distribution dist(20, 500);
        int delay_ms = dist(m_rng);

        // Choose destination: unicast back to querier, or multicast to the group
        endpoint dest = resp_mode == response_mode::unicast
                            ? sender
                            : endpoint{"224.0.0.251", 5353};

        // Arm response timer with delay; capture dest and qtype by value
        m_response_timer.expires_after(std::chrono::milliseconds(delay_ms));
        m_response_timer.async_wait(
            [this, dest, qtype](std::error_code ec)
            {
                if(ec || m_stopped.load(std::memory_order_acquire))
                    return;
                send_response(dest, qtype);
            });
    }

    // Builds and sends a DNS response to dest for the given qtype.
    void send_response(const endpoint &dest, dns_type qtype)
    {
        auto response = detail::build_dns_response(m_info, qtype);
        if(response.empty())
            return;

        m_socket.send(dest, std::span<const std::byte>(response));
    }

    // Sends an unsolicited announcement with all records (PTR, SRV, TXT, A/AAAA)
    // to the multicast group. RFC 6762 section 8.4.
    void send_announcement()
    {
        auto response = detail::build_dns_response(m_info, dns_type::any);
        if(!response.empty())
            m_socket.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(response));
    }

    std::shared_ptr<bool> m_alive = std::make_shared<bool>(true);
    executor_type m_executor;
    socket_type m_socket;
    timer_type m_response_timer;
    timer_type m_recv_timer;
    service_info m_info;
    service_options m_opts;
    completion_handler m_on_ready;
    completion_handler m_on_completion;
    std::mt19937 m_rng;
    std::unique_ptr<recv_loop<P>> m_loop;
    server_state m_state{server_state::idle};
    unsigned m_probe_count{0};
    unsigned m_announce_count{0};
    unsigned m_conflict_attempt{0};
    std::atomic<bool> m_stopped;
};

}

#endif

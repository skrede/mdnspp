#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"
#include "mdnspp/detail/server_query_match.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/server_probe_announce.h"
#include "mdnspp/detail/server_response_aggregation.h"

#include <span>
#include <string>
#include <memory>
#include <random>
#include <chrono>
#include <cstdint>
#include <cassert>
#include <utility>
#include <string_view>
#include <system_error>

namespace mdnspp {

// basic_service_server<P> -- mDNS service responder
//
// Policy-based class template parameterized on:
//   P -- Policy: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. Construct with (ex, info, opts, sock_opts) or non-throwing overload
//   2. async_start(on_ready, on_done) -- begins probe -> announce -> live sequence
//      on_ready fires with error_code{} when live, or probe_conflict on conflict
//      on_done fires with error_code{} when stop() is called
//   3. stop() -- idempotent; cancels probing/announcing, fires on_ready with
//      operation_canceled if not yet live, then fires on_done
//   4. ~basic_service_server() -- calls stop() for RAII safety

template <Policy P>
class basic_service_server : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;
    using server_state = detail::server_state;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;

    /// Optional callback invoked when an incoming query is received and parsed.
    /// Parameters: sender endpoint, qtype requested, response mode (unicast or multicast).
    using query_callback = detail::move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)>;

    /// Completion callback fired once when stop() is called or on_ready event occurs.
    /// Receives error_code.
    using completion_handler = detail::move_only_function<void(std::error_code)>;

    /// Error handler invoked on fire-and-forget send failures.
    /// Receives the error_code and a context string identifying the send site.
    using error_handler = detail::move_only_function<void(std::error_code, std::string_view)>;

    // Non-copyable
    basic_service_server(const basic_service_server &) = delete;
    basic_service_server &operator=(const basic_service_server &) = delete;

    // Movable only before async_start() is called (m_loop must be null).
    // Moving a started server is a logic error.
    basic_service_server(basic_service_server &&other) noexcept
        : base(std::move(other))
        , m_response_timer(std::move(other.m_response_timer))
        , m_info(std::move(other.m_info))
        , m_opts(std::move(other.m_opts))
        , m_on_ready(std::move(other.m_on_ready))
        , m_on_completion(std::move(other.m_on_completion))
        , m_on_error(std::move(other.m_on_error))
        , m_rng(std::move(other.m_rng))
        , m_pa_state(other.m_pa_state)
        , m_pending(other.m_pending)
    {
    }

    basic_service_server &operator=(basic_service_server &&other) noexcept
    {
        if(this == &other)
            return *this;
        assert(this->m_loop == nullptr);       // this server must not be started
        assert(other.m_loop == nullptr); // source must not be started
        // Move base members via a placement trick is not possible with private
        // inheritance, so we move each accessible member individually.
        this->m_alive = std::move(other.m_alive);
        this->m_executor = other.m_executor;
        this->m_socket = std::move(other.m_socket);
        this->m_timer = std::move(other.m_timer);
        this->m_loop = std::move(other.m_loop);
        this->m_stopped.store(other.m_stopped.load(std::memory_order_acquire),
                              std::memory_order_release);
        other.m_stopped.store(true, std::memory_order_release);
        m_response_timer = std::move(other.m_response_timer);
        m_info = std::move(other.m_info);
        m_opts = std::move(other.m_opts);
        m_on_ready = std::move(other.m_on_ready);
        m_on_completion = std::move(other.m_on_completion);
        m_on_error = std::move(other.m_on_error);
        m_rng = std::move(other.m_rng);
        m_pa_state = other.m_pa_state;
        m_pending = other.m_pending;
        return *this;
    }

    ~basic_service_server()
    {
        this->m_alive.reset(); // invalidate sentinel first
        if(this->m_loop)
            this->m_loop->stop(); // synchronously close socket/timer before members die
        stop();                   // then stop (posts teardown; guard will fail safely)
    }

    // Throwing constructor
    explicit basic_service_server(executor_type ex, service_info info,
                                  service_options opts = {},
                                  socket_options sock_opts = {})
        : base(ex, sock_opts)
        , m_response_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
    {
    }

    // Non-throwing constructor
    basic_service_server(executor_type ex, service_info info,
                         service_options opts, socket_options sock_opts,
                         std::error_code &ec)
        : base(ex, sock_opts, ec)
        , m_response_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
    {
    }

    // async_start() -- begins the probe -> announce -> live sequence.
    // on_ready fires after probe+announce completes (success) or on conflict.
    // on_done fires when stop() is called.
    // Must only be called once; calling async_start() twice is a logic error.
    void async_start(completion_handler on_ready = {}, completion_handler on_done = {})
    {
        assert(m_pa_state.state == server_state::idle);
        if(on_ready)
            m_on_ready = std::move(on_ready);
        if(on_done)
            m_on_completion = std::move(on_done);
        do_start();
    }

    /// Sets the error handler invoked on fire-and-forget send failures.
    void on_error(error_handler handler) { m_on_error = std::move(handler); }

    // stop() -- idempotent; posts teardown to the executor thread, ensuring all
    // state mutations happen on the executor (no cross-thread data race).
    //
    // The goodbye send happens on the caller thread (best-effort, before posting)
    // because the destructor invalidates m_alive before stop() runs, and the
    // goodbye must complete before that invalidation.
    void stop()
    {
        if(this->m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        // Best-effort goodbye on caller thread -- non-throwing via ec overload.
        if(m_opts.send_goodbye &&
           (m_pa_state.state == server_state::live || m_pa_state.state == server_state::announcing))
        {
            std::error_code ec;
            auto goodbye = detail::build_dns_response(m_info, dns_type::any, 0);
            if(!goodbye.empty())
                this->m_socket.send(endpoint{"224.0.0.251", 5353},
                              std::as_bytes(std::span(goodbye)), ec);
            if(ec && m_on_error) m_on_error(ec, "goodbye send");
        }

        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard]()
        {
            if(!guard.lock()) return;

            if(m_pa_state.state == server_state::probing || m_pa_state.state == server_state::announcing)
            {
                if(auto h = std::exchange(m_on_ready, nullptr); h)
                    h(std::make_error_code(std::errc::operation_canceled));
            }

            m_pa_state.state = server_state::stopped;
            m_pending.armed = false;
            m_response_timer.cancel();

            if(this->m_loop)
                this->m_loop->stop();

            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::error_code{});
        });
    }

    // update_service_info() -- posts a service info replacement to the event loop.
    // After the update executes, an announcement burst is sent with announce_count
    // announcements at announce_interval intervals per RFC 6762 section 8.4.
    // Must only be called on a running server (after async_start(), before stop()).
    // Thread-safe: may be called from any thread.
    void update_service_info(service_info new_info)
    {
        assert(!this->m_stopped.load(std::memory_order_acquire)); // must be running
        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard, info = std::move(new_info)]() mutable
        {
            if(!guard.lock()) return;
            if(this->m_stopped.load(std::memory_order_acquire)) return;
            m_info = std::move(info);
            m_pa_state.announce_count = 0;
            send_update_announce();
        });
    }

    // Server-specific timer accessors:
    // timer() returns the response timer (used for probing/announcing/response delays)
    // recv_timer() returns the base timer (used by recv_loop)
    const timer_type &timer() const noexcept { return m_response_timer; }
    timer_type &timer() noexcept { return m_response_timer; }
    const timer_type &recv_timer() const noexcept { return base::timer(); }
    timer_type &recv_timer() noexcept { return base::timer(); }

private:
    // Common start body -- creates recv_loop and begins probing.
    void do_start()
    {
        this->m_loop = std::make_unique<recv_loop<P>>(
            this->m_socket,
            this->m_timer,
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
        this->m_loop->start();
    }

    void start_probing()
    {
        detail::begin_probing(m_pa_state);

        // Generate a random transaction ID for our probes so we can
        // distinguish our own looped-back packets from another host's probes.
        // Use a non-zero value; zero could collide with the mDNS default.
        std::uniform_int_distribution<uint16_t> id_dist(1, 0xFFFF);
        m_pa_state.probe_id = id_dist(m_rng);

        // Random delay 0-250ms before first probe (RFC 6762 section 8.1)
        std::uniform_int_distribution dist(0, 250);
        m_response_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_pa_state.state != server_state::probing) return;
            if(this->m_stopped.load(std::memory_order_acquire)) return;
            send_probe();
        });
    }

    void send_probe()
    {
        if(m_pa_state.state != server_state::probing) return;
        if(this->m_stopped.load(std::memory_order_acquire)) return;

        auto probe = detail::build_probe_query(m_info);
        // Stamp our probe ID into the DNS header transaction ID (bytes 0-1)
        probe[0] = static_cast<std::byte>(m_pa_state.probe_id >> 8);
        probe[1] = static_cast<std::byte>(m_pa_state.probe_id & 0xFF);
        std::error_code ec;
        this->m_socket.send(endpoint{"224.0.0.251", 5353}, std::span<const std::byte>(probe), ec);
        if(ec && m_on_error) m_on_error(ec, "probe send");

        bool more = detail::advance_probe(m_pa_state);
        m_response_timer.expires_after(std::chrono::milliseconds(250));
        m_response_timer.async_wait([this, more](std::error_code ec)
        {
            if(ec || m_pa_state.state != server_state::probing) return;
            if(this->m_stopped.load(std::memory_order_acquire)) return;
            if(more)
                send_probe();
            else
                start_announcing();
        });
    }

    void start_announcing()
    {
        detail::begin_announcing(m_pa_state);
        send_announce();
    }

    void send_announce()
    {
        if(m_pa_state.state != server_state::announcing) return;
        if(this->m_stopped.load(std::memory_order_acquire)) return;

        send_announcement();
        bool more = detail::advance_announce(m_pa_state, m_opts.announce_count);

        if(more)
        {
            m_response_timer.expires_after(m_opts.announce_interval);
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || m_pa_state.state != server_state::announcing) return;
                if(this->m_stopped.load(std::memory_order_acquire)) return;
                send_announce();
            });
        }
        else
        {
            // Probe+announce complete -- server is live
            m_pa_state.state = server_state::live;
            if(auto h = std::exchange(m_on_ready, nullptr); h)
                h(std::error_code{});
        }
    }

    void handle_conflict()
    {
        m_response_timer.cancel();

        if(m_opts.on_conflict)
        {
            std::string new_name;
            if(m_opts.on_conflict(m_info.service_name, new_name, m_pa_state.conflict_attempt))
            {
                m_info.service_name = std::move(new_name);
                ++m_pa_state.conflict_attempt;
                start_probing();
                return;
            }
        }

        // No callback or callback returned false -- fail
        m_pa_state.state = server_state::stopped;
        this->m_stopped.store(true, std::memory_order_release);
        if(auto h = std::exchange(m_on_ready, nullptr); h)
            h(mdns_error::probe_conflict);
    }

    void send_update_announce()
    {
        if(this->m_stopped.load(std::memory_order_acquire)) return;
        if(m_pa_state.state != server_state::live) return;

        send_announcement();
        bool more = detail::advance_announce(m_pa_state, m_opts.announce_count);

        if(more)
        {
            m_response_timer.expires_after(m_opts.announce_interval);
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || this->m_stopped.load(std::memory_order_acquire)) return;
                if(m_pa_state.state != server_state::live) return;
                send_update_announce();
            });
        }
    }

    // Checks if an incoming DNS response contains records matching our probed names.
    bool response_conflicts(std::span<std::byte> data) const
    {
        bool conflict = false;
        detail::walk_dns_frame(std::span<const std::byte>(data.data(), data.size()),
            endpoint{}, [&](mdns_record_variant rv)
        {
            auto sn = detail::strip_dot(m_info.service_name);
            auto hn = detail::strip_dot(m_info.hostname);
            std::visit([&](const auto &rec)
            {
                if(rec.name == sn || rec.name == hn)
                    conflict = true;
            }, rv);
        });
        return conflict;
    }

    void send_to(response_mode mode, const endpoint &sender,
                  std::span<const std::byte> packet, std::string_view context)
    {
        std::error_code ec;
        if(mode == response_mode::unicast)
            this->m_socket.send(sender, packet, ec);
        else
            this->m_socket.send(endpoint{"224.0.0.251", 5353}, packet, ec);
        if(ec && m_on_error) m_on_error(ec, context);
    }

    void schedule_multicast_response(const detail::query_match_result &qmr,
                                     const detail::suppression_mask &suppression)
    {
        bool was_armed = m_pending.armed;
        m_pending.merge(qmr.accumulated_qtype, qmr.needs_nsec, suppression);
        if(was_armed)
            return; // timer already running, merge is enough

        // RFC 6762 section 6: random delay 20-120ms before responding via multicast
        std::uniform_int_distribution dist(20, 120);
        m_response_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || this->m_stopped.load(std::memory_order_acquire))
                return;
            if(m_pa_state.state != server_state::live)
                return;

            auto response = detail::build_response_with_nsec(m_info, m_pending.qtype,
                                                             m_pending.needs_nsec,
                                                             m_pending.suppression,
                                                             m_opts.suppress_known_answers);
            m_pending.reset();
            if(!response.empty())
                send_to(response_mode::multicast, {}, std::span<const std::byte>(response), "response send");
        });
    }

    // Called by recv_loop on every incoming packet.
    void on_query(const endpoint &sender, std::span<std::byte> data)
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return;

        // During probing: check for conflicting responses and simultaneous probes
        if(m_pa_state.state == server_state::probing)
        {
            if(data.size() >= 12)
            {
                uint16_t flags = detail::read_u16_be(data.data() + 2);
                if(flags & 0x8000)
                {
                    // Response from an authoritative owner of the name
                    if(response_conflicts(data))
                        handle_conflict();
                }
                else
                {
                    // Query -- check for simultaneous probe (RFC 6762 section 8.2).
                    // A probe carries proposed records in the Authority section;
                    // if it contains our name, another host is probing for the same name.
                    // Skip our own looped-back probes by comparing the transaction ID.
                    uint16_t id = detail::read_u16_be(data.data());
                    uint16_t nscount = detail::read_u16_be(data.data() + 8);
                    if(id != m_pa_state.probe_id && nscount > 0 && response_conflicts(data))
                        handle_conflict();
                }
            }
            return;
        }

        if(m_pa_state.state != server_state::live)
            return;

        auto cdata = std::span<const std::byte>(data.data(), data.size());
        auto qmr = detail::match_queries(cdata, m_info, m_opts);
        if(!qmr.any_matched && !qmr.meta_matched && qmr.matched_subtype.empty())
            return;

        detail::suppression_mask suppression;
        if(m_opts.suppress_known_answers && qmr.any_matched)
            suppression = detail::parse_known_answers(cdata, qmr.offset_after_questions, m_info);

        if(m_opts.on_query && qmr.any_matched)
            m_opts.on_query(sender, qmr.accumulated_qtype, qmr.mode);

        if(qmr.meta_matched)
        {
            auto pkt = detail::build_meta_query_response(m_info);
            send_to(qmr.mode, sender, std::span<const std::byte>(pkt), "meta-query response send");
        }

        if(!qmr.matched_subtype.empty())
        {
            auto pkt = detail::build_subtype_response(qmr.matched_subtype, m_info);
            send_to(qmr.mode, sender, std::span<const std::byte>(pkt), "subtype response send");
        }

        if(!qmr.any_matched)
            return;

        if(m_opts.suppress_known_answers && detail::all_suppressed(suppression, qmr.accumulated_qtype, m_info))
            return;

        if(qmr.mode == response_mode::unicast)
        {
            auto pkt = detail::build_response_with_nsec(m_info, qmr.accumulated_qtype,
                                                        qmr.needs_nsec, suppression,
                                                        m_opts.suppress_known_answers);
            if(!pkt.empty())
                send_to(response_mode::unicast, sender, std::span<const std::byte>(pkt), "response send");
            return;
        }

        schedule_multicast_response(qmr, suppression);
    }

    // Sends an unsolicited announcement with all records (PTR, SRV, TXT, A/AAAA)
    // to the multicast group. RFC 6762 section 8.4.
    // When respond_to_meta_queries is true, also includes the DNS-SD service type
    // enumeration PTR record (_services._dns-sd._udp.local -> service_type)
    // per RFC 6763 section 9.
    // When announce_subtypes is true, also sends subtype PTR records.
    void send_announcement()
    {
        auto response = detail::build_dns_response(m_info, dns_type::any);
        if(!response.empty())
            send_to(response_mode::multicast, {}, std::span<const std::byte>(response), "announcement send");

        if(m_opts.respond_to_meta_queries)
        {
            auto pkt = detail::build_meta_query_response(m_info);
            if(!pkt.empty())
                send_to(response_mode::multicast, {}, std::span<const std::byte>(pkt), "announcement send");
        }

        if(m_opts.announce_subtypes)
        {
            for(const auto &sub : m_info.subtypes)
            {
                auto pkt = detail::build_subtype_response(sub, m_info);
                if(!pkt.empty())
                    send_to(response_mode::multicast, {}, std::span<const std::byte>(pkt), "announcement send");
            }
        }
    }

    timer_type m_response_timer;
    service_info m_info;
    service_options m_opts;
    completion_handler m_on_ready;
    completion_handler m_on_completion;
    error_handler m_on_error;
    std::mt19937 m_rng;
    detail::probe_announce_state m_pa_state;
    detail::pending_response m_pending;
};

}

#endif

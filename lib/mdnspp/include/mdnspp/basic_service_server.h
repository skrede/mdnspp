#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/tc_accumulator.h"
#include "mdnspp/detail/server_query_match.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"
#include "mdnspp/detail/server_probe_announce.h"
#include "mdnspp/detail/server_response_aggregation.h"
#include "mdnspp/detail/duplicate_answer_suppression.h"

#include <span>
#include <string>
#include <memory>
#include <random>
#include <chrono>
#include <vector>
#include <cstdint>
#include <cassert>
#include <utility>
#include <algorithm>
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
    using completion_handler = mdnspp::server_completion_handler;

    /// Error handler invoked on fire-and-forget send failures.
    /// Receives the error_code and a context string identifying the send site.
    using error_handler = mdnspp::error_handler;

    // Non-copyable
    basic_service_server(const basic_service_server &) = delete;
    basic_service_server &operator=(const basic_service_server &) = delete;

    // Movable only before async_start() is called (m_loop must be null).
    // Moving a started server is a logic error.
    basic_service_server(basic_service_server &&other) noexcept
        : base(std::move(other))
        , m_response_timer(std::move(other.m_response_timer))
        , m_tc_timer(std::move(other.m_tc_timer))
        , m_info(std::move(other.m_info))
        , m_opts(std::move(other.m_opts))
        , m_on_ready(std::move(other.m_on_ready))
        , m_on_completion(std::move(other.m_on_completion))
        , m_on_error(std::move(other.m_on_error))
        , m_rng(std::move(other.m_rng))
        , m_pa_state(other.m_pa_state)
        , m_pending(other.m_pending)
        , m_tc_acc(std::move(other.m_tc_acc))
        , m_dup_suppression(std::move(other.m_dup_suppression))
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
        this->m_mdns_opts = std::move(other.m_mdns_opts);
        m_response_timer = std::move(other.m_response_timer);
        m_tc_timer = std::move(other.m_tc_timer);
        m_info = std::move(other.m_info);
        m_opts = std::move(other.m_opts);
        m_on_ready = std::move(other.m_on_ready);
        m_on_completion = std::move(other.m_on_completion);
        m_on_error = std::move(other.m_on_error);
        m_rng = std::move(other.m_rng);
        m_pa_state = other.m_pa_state;
        m_pending = other.m_pending;
        m_tc_acc = std::move(other.m_tc_acc);
        m_dup_suppression = std::move(other.m_dup_suppression);
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
                                  socket_options sock_opts = {},
                                  mdns_options mdns_opts = {})
        : base(ex, sock_opts, std::move(mdns_opts))
        , m_response_timer(ex)
        , m_tc_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
    {
    }

    // Non-throwing constructor
    basic_service_server(executor_type ex, service_info info,
                         service_options opts, socket_options sock_opts,
                         mdns_options mdns_opts, std::error_code &ec)
        : base(ex, sock_opts, std::move(mdns_opts), ec)
        , m_response_timer(ex)
        , m_tc_timer(ex)
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
            // Goodbye uses TTL=0 for all record types (RFC 6762 §11.3).
            service_options goodbye_opts;
            goodbye_opts.ptr_ttl    = std::chrono::seconds{0};
            goodbye_opts.srv_ttl    = std::chrono::seconds{0};
            goodbye_opts.txt_ttl    = std::chrono::seconds{0};
            goodbye_opts.a_ttl      = std::chrono::seconds{0};
            goodbye_opts.aaaa_ttl   = std::chrono::seconds{0};
            goodbye_opts.record_ttl = std::chrono::seconds{0};
            auto goodbye = detail::build_dns_response(m_info, dns_type::any, goodbye_opts);
            if(!goodbye.empty())
                this->m_socket.send(this->multicast_endpoint(),
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
            m_tc_timer.cancel();
            m_tc_acc.clear();

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
    // tc_timer() returns the dedicated TC wait timer (RFC 6762 §6 truncated-response accumulation)
    // recv_timer() returns the base timer (used by recv_loop)
    const timer_type &timer() const noexcept { return m_response_timer; }
    timer_type &timer() noexcept { return m_response_timer; }
    const timer_type &tc_timer() const noexcept { return m_tc_timer; }
    timer_type &tc_timer() noexcept { return m_tc_timer; }
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
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                on_query(meta.sender, data);
                return true;
            },
            []()
            {
                // no-op on silence
            },
            this->m_mdns_opts.receive_ttl_minimum);

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

        // Random delay [0, probe_initial_delay_max] before first probe (RFC 6762 section 8.1)
        std::uniform_int_distribution dist(0, static_cast<int>(m_opts.probe_initial_delay_max.count()));
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

        auto probe = detail::build_probe_query(m_info, static_cast<uint32_t>(m_opts.probe_authority_ttl.count()));
        // Stamp our probe ID into the DNS header transaction ID (bytes 0-1)
        probe[0] = static_cast<std::byte>(m_pa_state.probe_id >> 8);
        probe[1] = static_cast<std::byte>(m_pa_state.probe_id & 0xFF);
        std::error_code ec;
        this->m_socket.send(this->multicast_endpoint(), std::span<const std::byte>(probe), ec);
        if(ec && m_on_error) m_on_error(ec, "probe send");

        bool more = detail::advance_probe(m_pa_state, m_opts.probe_count);
        m_response_timer.expires_after(m_opts.probe_interval);
        m_response_timer.async_wait([this, more](std::error_code wait_ec)
        {
            if(wait_ec || m_pa_state.state != server_state::probing) return;
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

    void handle_conflict(conflict_type ct = conflict_type::name_conflict)
    {
        m_response_timer.cancel();

        if(m_opts.on_conflict)
        {
            std::string new_name;
            if(m_opts.on_conflict(m_info.service_name.str(), new_name, m_pa_state.conflict_attempt, ct))
            {
                if(ct == conflict_type::name_conflict)
                {
                    m_info.service_name = std::move(new_name);
                    ++m_pa_state.conflict_attempt;
                }
                if(ct == conflict_type::tiebreak_deferred)
                {
                    // RFC 6762 section 8.2: loser defers and re-probes after probe_defer_delay
                    m_response_timer.expires_after(m_opts.probe_defer_delay);
                    m_response_timer.async_wait([this](std::error_code ec)
                    {
                        if(ec || this->m_stopped.load(std::memory_order_acquire)) return;
                        start_probing();
                    });
                    return;
                }
                start_probing();
                return;
            }
        }

        if(ct == conflict_type::tiebreak_deferred)
        {
            // No callback for tiebreak -- defer silently
            m_response_timer.expires_after(m_opts.probe_defer_delay);
            m_response_timer.async_wait([this](std::error_code ec)
            {
                if(ec || this->m_stopped.load(std::memory_order_acquire)) return;
                start_probing();
            });
            return;
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

    // Extracts the raw SRV rdata from the authority (NS) section of an incoming probe packet.
    // Returns empty vector if no SRV rdata found in authority.
    // Used for RFC 6762 section 8.2 simultaneous-probe tiebreaking.
    std::vector<std::byte> extract_authority_srv_rdata(std::span<const std::byte> data) const
    {
        if(data.size() < 12) return {};

        // Skip the question section
        uint16_t qdcount = detail::read_u16_be(data.data() + 4);
        uint16_t ancount = detail::read_u16_be(data.data() + 6);
        uint16_t nscount = detail::read_u16_be(data.data() + 8);

        if(nscount == 0) return {};

        std::size_t offset = 12;

        // Skip questions
        for(uint16_t i = 0; i < qdcount; ++i)
        {
            if(!detail::skip_dns_name(data, offset)) return {};
            if(offset + 4 > data.size()) return {};
            offset += 4; // qtype + qclass
        }

        // Skip answers
        for(uint16_t i = 0; i < ancount; ++i)
        {
            if(!detail::skip_dns_name(data, offset)) return {};
            if(offset + 10 > data.size()) return {};
            offset += 4; // rtype + rclass
            offset += 4; // ttl
            uint16_t rdlen = detail::read_u16_be(data.data() + offset);
            offset += 2;
            if(offset + rdlen > data.size()) return {};
            offset += rdlen;
        }

        // Read first authority section SRV record rdata
        for(uint16_t i = 0; i < nscount; ++i)
        {
            std::size_t rr_start = offset;
            if(!detail::skip_dns_name(data, offset)) return {};
            if(offset + 10 > data.size()) return {};
            uint16_t rtype = detail::read_u16_be(data.data() + offset);
            offset += 4; // rtype + rclass
            offset += 4; // ttl
            uint16_t rdlen = detail::read_u16_be(data.data() + offset);
            offset += 2;
            if(offset + rdlen > data.size()) return {};

            if(rtype == std::to_underlying(dns_type::srv))
            {
                return std::vector<std::byte>(data.data() + offset,
                                             data.data() + offset + rdlen);
            }
            offset += rdlen;
            (void)rr_start;
        }

        return {};
    }

    // Builds the raw SRV rdata for our proposed record (for tiebreaking comparison).
    std::vector<std::byte> build_our_srv_rdata() const
    {
        std::vector<std::byte> rdata;
        detail::push_u16_be(rdata, m_info.priority);
        detail::push_u16_be(rdata, m_info.weight);
        detail::push_u16_be(rdata, m_info.port);
        auto host = detail::encode_dns_name(m_info.hostname);
        rdata.insert(rdata.end(), host.begin(), host.end());
        return rdata;
    }

    // Checks if an incoming DNS response contains records matching our probed names.
    bool response_conflicts(std::span<std::byte> data) const
    {
        bool conflict = false;
        detail::walk_dns_frame(std::span<const std::byte>(data.data(), data.size()),
            endpoint{}, [&](mdns_record_variant rv)
        {
            std::visit([&](const auto &rec)
            {
                if(rec.name == m_info.service_name || rec.name == m_info.hostname)
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
            this->m_socket.send(this->multicast_endpoint(), packet, ec);
        if(ec && m_on_error) m_on_error(ec, context);
    }

    void schedule_multicast_response(const detail::query_match_result &qmr,
                                     const detail::suppression_mask &suppression)
    {
        bool was_armed = m_pending.armed;
        m_pending.merge(qmr.accumulated_qtype, qmr.needs_nsec, suppression);
        if(was_armed)
            return; // timer already running, merge is enough

        // RFC 6762 section 6: random delay [response_delay_min, response_delay_max] before responding via multicast
        std::uniform_int_distribution dist(static_cast<int>(this->m_mdns_opts.response_delay_min.count()),
                                           static_cast<int>(this->m_mdns_opts.response_delay_max.count()));
        m_response_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || this->m_stopped.load(std::memory_order_acquire))
                return;
            if(m_pa_state.state != server_state::live)
                return;

            // RFC 6762 §7.4: merge duplicate suppression observations into suppression mask.
            // Build the exact records we would send and check each against m_dup_suppression.
            // Using the round-trip serialised+parsed form ensures identity equality matches.
            // Duplicate suppression threshold uses record_ttl as a single scalar baseline.
            uint32_t dup_threshold = static_cast<uint32_t>(m_opts.record_ttl.count());
            auto combined = m_pending.suppression;
            if(!m_dup_suppression.empty())
            {
                auto candidate_pkt = detail::build_dns_response(m_info, dns_type::any, m_opts);
                std::vector<mdns_record_variant> candidates;
                detail::walk_dns_frame(
                    std::span<const std::byte>(candidate_pkt.data(), candidate_pkt.size()),
                    endpoint{},
                    [&](mdns_record_variant rv) { candidates.push_back(std::move(rv)); });

                for(const auto &rec : candidates)
                {
                    if(!m_dup_suppression.is_suppressed(rec, dup_threshold))
                        continue;
                    std::visit([&](const auto &r)
                    {
                        using T = std::decay_t<decltype(r)>;
                        if constexpr (std::is_same_v<T, record_ptr>)   combined.ptr  = true;
                        else if constexpr (std::is_same_v<T, record_srv>)  combined.srv  = true;
                        else if constexpr (std::is_same_v<T, record_a>)    combined.a    = true;
                        else if constexpr (std::is_same_v<T, record_aaaa>) combined.aaaa = true;
                        else if constexpr (std::is_same_v<T, record_txt>)  combined.txt  = true;
                    }, rec);
                }
            }
            m_dup_suppression.reset();

            auto response = detail::build_response_with_nsec(m_info, m_pending.qtype,
                                                             m_pending.needs_nsec,
                                                             combined,
                                                             m_opts.suppress_known_answers,
                                                             m_opts);
            m_pending.reset();
            if(!response.empty())
                send_to(response_mode::multicast, {}, std::span<const std::byte>(response), "response send");
        });
    }

    // Parses the answer section of a DNS packet into a flat record list.
    // Used for TC known-answer accumulation and duplicate suppression observation.
    std::vector<mdns_record_variant> parse_answer_records(std::span<const std::byte> data)
    {
        std::vector<mdns_record_variant> records;
        detail::walk_dns_frame(data, endpoint{}, [&](mdns_record_variant rv)
        {
            records.push_back(std::move(rv));
        });
        return records;
    }

    // Called by recv_loop on every incoming packet.
    void on_query(const endpoint &sender, std::span<std::byte> data)
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return;

        // During probing: check for conflicting responses and simultaneous probes
        if(m_pa_state.state == server_state::probing)
        {
            if(data.size() < 12)
                return;

            uint16_t flags = detail::read_u16_be(data.data() + 2);
            if(flags & 0x8000)
            {
                // Response from an authoritative owner of the name (QR=1)
                if(response_conflicts(data))
                    handle_conflict(conflict_type::name_conflict);
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
                {
                    // RFC 6762 section 8.2 tiebreaking: compare our proposed SRV rdata
                    // with the received authority SRV rdata lexicographically.
                    // If our record is greater, we win -- continue probing (do nothing).
                    // If our record is lesser or equal, we lose -- defer and re-probe.
                    auto our_rdata   = build_our_srv_rdata();
                    auto their_rdata = extract_authority_srv_rdata(
                        std::span<const std::byte>(data.data(), data.size()));

                    if(their_rdata.empty())
                    {
                        // No parseable SRV in authority -- fall back to name conflict
                        handle_conflict(conflict_type::name_conflict);
                    }
                    else
                    {
                        int cmp = detail::compare_authority_records(
                            std::span<const std::byte>(our_rdata),
                            std::span<const std::byte>(their_rdata));
                        if(cmp <= 0)
                        {
                            // We lose the tiebreak -- defer
                            detail::begin_probing(m_pa_state);
                            handle_conflict(conflict_type::tiebreak_deferred);
                        }
                        // else: we win -- continue probing (do nothing)
                    }
                }
            }
            return;
        }

        if(m_pa_state.state != server_state::live)
            return;

        if(data.size() < 12)
            return;

        uint16_t flags = detail::read_u16_be(data.data() + 2);
        bool is_response = (flags & 0x8000) != 0;
        bool tc_set = (flags & 0x0200) != 0;

        auto cdata = std::span<const std::byte>(data.data(), data.size());

        // RFC 6762 §7.4: observe multicast responses during 20-120ms response delay
        // to suppress answers that another responder has already sent.
        if(is_response)
        {
            auto answer_records = parse_answer_records(cdata);
            for(const auto &rec : answer_records)
            {
                uint32_t observed_ttl = std::visit([](const auto &r) { return r.ttl; }, rec);
                m_dup_suppression.observe(rec, observed_ttl);
            }
            return;
        }

        // RFC 6762 §6: TC (Truncated) bit set -- defer processing for 400-500ms
        // to allow continuation packets to arrive from the same sender.
        if(tc_set)
        {
            auto answer_records = parse_answer_records(cdata);
            bool is_first = !m_tc_acc.has_pending(sender);
            m_tc_acc.accumulate(sender, std::move(answer_records),
                                this->m_mdns_opts.tc_wait_min);

            if(is_first)
            {
                // Arm the TC timer only once per source (first packet).
                std::uniform_int_distribution<int> dist(
                    static_cast<int>(this->m_mdns_opts.tc_wait_min.count()),
                    static_cast<int>(this->m_mdns_opts.tc_wait_max.count()));
                auto tc_wait = std::chrono::milliseconds(dist(m_rng));

                m_tc_timer.expires_after(tc_wait);
                m_tc_timer.async_wait([this, sender, tc_wait](std::error_code ec)
                {
                    if(ec || this->m_stopped.load(std::memory_order_acquire))
                        return;
                    on_tc_wait_expired(sender, tc_wait);
                });
            }
            return;
        }

        // Normal (non-TC) query processing.
        // If the sender has pending TC entries, continue accumulating but also
        // proceed immediately with what we have.

        // RFC 6762 section 6.7: legacy unicast detection.
        // Queries from non-5353 ports (and non-zero ports, i.e. a real port) are
        // legacy unicast; respond directly via unicast with TTLs capped at
        // mdns_options::legacy_unicast_ttl. Port=0 is treated as multicast (test/unknown).
        if(m_opts.respond_to_legacy_unicast && sender.port != 0 && sender.port != 5353)
        {
            auto qmr = detail::match_queries(cdata, m_info, m_opts);
            if(qmr.any_matched)
            {
                uint32_t legacy_cap = static_cast<uint32_t>(this->m_mdns_opts.legacy_unicast_ttl.count());
                auto pkt = detail::build_dns_response(m_info, qmr.accumulated_qtype, m_opts, legacy_cap);
                if(!pkt.empty())
                    send_to(response_mode::unicast, sender, std::span<const std::byte>(pkt), "legacy unicast response");
            }
            return;
        }

        auto qmr = detail::match_queries(cdata, m_info, m_opts);
        if(!qmr.any_matched && !qmr.meta_matched && qmr.matched_subtype.empty())
            return;

        detail::suppression_mask suppression;
        if(m_opts.suppress_known_answers && qmr.any_matched)
        {
            uint32_t ka_threshold = static_cast<uint32_t>(
                static_cast<double>(this->m_mdns_opts.record_ttl.count()) * this->m_mdns_opts.ka_suppression_fraction);
            suppression = detail::parse_known_answers(cdata, qmr.offset_after_questions, m_info, ka_threshold);
        }

        if(m_opts.on_query && qmr.any_matched)
            m_opts.on_query(sender, qmr.accumulated_qtype, qmr.mode);

        if(qmr.meta_matched)
        {
            uint32_t meta_ttl = static_cast<uint32_t>(m_opts.record_ttl.count());
            auto pkt = detail::build_meta_query_response(m_info, meta_ttl);
            send_to(qmr.mode, sender, std::span<const std::byte>(pkt), "meta-query response send");
        }

        if(!qmr.matched_subtype.empty())
        {
            uint32_t sub_ttl = static_cast<uint32_t>(m_opts.record_ttl.count());
            auto pkt = detail::build_subtype_response(qmr.matched_subtype, m_info, sub_ttl);
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
                                                        m_opts.suppress_known_answers,
                                                        m_opts);
            if(!pkt.empty())
                send_to(response_mode::unicast, sender, std::span<const std::byte>(pkt), "response send");
            return;
        }

        schedule_multicast_response(qmr, suppression);
    }

    // Called when the TC wait timer fires for a given sender.
    // Takes the accumulated known-answers from m_tc_acc and processes the stored
    // query with the merged known-answer set.
    void on_tc_wait_expired(const endpoint &sender, std::chrono::milliseconds tc_wait)
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return;
        if(m_pa_state.state != server_state::live)
            return;

        // Pass time_point::max() as 'now': the timer firing IS the ready signal.
        // take_if_ready's time guard is redundant here but kept for robustness.
        auto merged = m_tc_acc.take_if_ready(sender,
                                             (std::chrono::steady_clock::time_point::max)(), tc_wait);
        if(!merged.has_value())
            return;

        if(m_opts.on_tc_continuation)
            m_opts.on_tc_continuation(sender, merged->size());

        // Build a synthetic suppression mask from the merged known-answers.
        // The merged records ARE the known-answer list accumulated over TC packets;
        // treat them as suppression candidates for our service.
        detail::suppression_mask suppression;
        uint32_t ka_threshold = static_cast<uint32_t>(
            static_cast<double>(this->m_mdns_opts.record_ttl.count()) * this->m_mdns_opts.tc_suppression_fraction);
        for(const auto &rec : *merged)
        {
            std::visit([&](const auto &r)
            {
                bool name_ok = (r.name == m_info.service_name
                             || r.name == m_info.service_type
                             || r.name == m_info.hostname);
                if(name_ok && r.ttl >= ka_threshold)
                {
                    using T = std::decay_t<decltype(r)>;
                    if constexpr (std::is_same_v<T, record_ptr>)   suppression.ptr  = true;
                    else if constexpr (std::is_same_v<T, record_srv>)  suppression.srv  = true;
                    else if constexpr (std::is_same_v<T, record_a>)    suppression.a    = true;
                    else if constexpr (std::is_same_v<T, record_aaaa>) suppression.aaaa = true;
                    else if constexpr (std::is_same_v<T, record_txt>)  suppression.txt  = true;
                }
            }, rec);
        }

        // Respond with dns_type::any using the merged suppression mask.
        detail::query_match_result qmr;
        qmr.any_matched = true;
        qmr.accumulated_qtype = dns_type::any;
        qmr.mode = response_mode::multicast;
        qmr.needs_nsec = false;

        if(m_opts.suppress_known_answers && detail::all_suppressed(suppression, dns_type::any, m_info))
            return;

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
        uint32_t ann_ttl = static_cast<uint32_t>(m_opts.record_ttl.count());
        auto response = detail::build_dns_response(m_info, dns_type::any, m_opts);
        if(!response.empty())
            send_to(response_mode::multicast, {}, std::span<const std::byte>(response), "announcement send");

        if(m_opts.respond_to_meta_queries)
        {
            auto pkt = detail::build_meta_query_response(m_info, ann_ttl);
            if(!pkt.empty())
                send_to(response_mode::multicast, {}, std::span<const std::byte>(pkt), "announcement send");
        }

        if(m_opts.announce_subtypes)
        {
            for(const auto &sub : m_info.subtypes)
            {
                auto pkt = detail::build_subtype_response(sub, m_info, ann_ttl);
                if(!pkt.empty())
                    send_to(response_mode::multicast, {}, std::span<const std::byte>(pkt), "announcement send");
            }
        }
    }

    timer_type m_response_timer;
    timer_type m_tc_timer;
    service_info m_info;
    service_options m_opts;
    completion_handler m_on_ready;
    completion_handler m_on_completion;
    error_handler m_on_error;
    std::mt19937 m_rng;
    detail::probe_announce_state m_pa_state;
    detail::pending_response m_pending;
    detail::tc_accumulator<> m_tc_acc;
    detail::duplicate_suppression_state m_dup_suppression;
};

}

#endif

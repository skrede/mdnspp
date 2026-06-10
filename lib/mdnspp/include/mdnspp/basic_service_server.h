#ifndef HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H
#define HPP_GUARD_MDNSPP_BASIC_SERVICE_SERVER_H

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"
#include "mdnspp/callback_types.h"
#include "mdnspp/service_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/tc_accumulator.h"
#include "mdnspp/detail/server_validate.h"
#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/server_query_match.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/basic_mdns_peer_base.h"
#include "mdnspp/detail/server_probe_announce.h"
#include "mdnspp/detail/server_response_aggregation.h"
#include "mdnspp/detail/duplicate_answer_suppression.h"

#include <span>
#include <atomic>
#include <chrono>
#include <memory>
#include <random>
#include <string>
#include <vector>
#include <cassert>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace mdnspp {

// basic_service_server<P> -- mDNS service responder
//
// Policy-based class template parameterized on:
//   P -- policy_like: provides executor_type, socket_type, timer_type
//
// Lifecycle:
//   1. Construct with (ex, info, opts, sock_opts) or non-throwing overload.
//      Options are validated at construction; invalid combinations fail with
//      std::errc::invalid_argument (thrown as std::system_error, or reported
//      through the error_code overload).
//   2. async_start(on_ready, on_done) -- begins probe -> announce -> live sequence.
//      When service_info::auto_address is set (service_info::make()), the
//      unset address fields are resolved from the bound interface first
//      (RFC 6762 section 6.2); update_service_info re-resolves under the
//      same rule.
//      on_ready fires with error_code{} when live. On permanent probe failure
//      (conflict with no replacement name, or an unencodable name) on_ready
//      fires with the failure reason (mdns_error::probe_conflict /
//      std::errc::invalid_argument), the full teardown runs, and on_done then
//      fires with error_code{}.
//      async_start is one-shot: a second call (or a call after stop()) fails
//      deterministically by completing on_ready -- posted to the executor --
//      with std::errc::operation_in_progress / std::errc::invalid_argument.
//   3. stop() -- idempotent; posts the teardown (including building and
//      sending the goodbye packet) to the executor, fires on_ready with
//      operation_canceled if not yet live, then fires on_done with
//      error_code{}. A goodbye is sent only if the executor runs after
//      stop().
//   4. ~basic_service_server() -- calls stop() for RAII safety and completes
//      still-pending handlers with operation_canceled
//
// Non-copyable and non-movable: completion handlers capture `this`.

template <policy_like P>
class basic_service_server : detail::basic_mdns_peer_base<P>
{
    using base = detail::basic_mdns_peer_base<P>;
    using server_state = detail::server_state;
    using clock_type = std::chrono::steady_clock;

public:
    using typename base::executor_type;
    using typename base::socket_type;
    using typename base::timer_type;
    using base::socket;

    /// Optional callback invoked when an incoming query is received and parsed.
    /// Parameters: sender endpoint, qtype requested, response mode (unicast or multicast).
    using query_callback = move_only_function<void(const endpoint &sender, dns_type type, response_mode mode)>;

    /// Completion callback fired once when stop() is called or on_ready event occurs.
    /// Receives error_code.
    using completion_handler = mdnspp::server_completion_handler;

    // Non-copyable, non-movable
    basic_service_server(const basic_service_server &) = delete;
    basic_service_server &operator=(const basic_service_server &) = delete;
    basic_service_server(basic_service_server &&) = delete;
    basic_service_server &operator=(basic_service_server &&) = delete;

    ~basic_service_server()
    {
        this->m_alive.reset(); // invalidate sentinel first
        if(this->m_loop)
            this->m_loop->stop(); // synchronously close socket/timer before members die
        stop();                   // then stop (posts teardown; guard will fail safely)
        // The posted stop() teardown is dropped by the expired alive guard;
        // complete still-pending handlers instead of silently dropping them.
        if(auto h = std::exchange(m_on_ready, nullptr); h)
            h(std::make_error_code(std::errc::operation_canceled));
        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::make_error_code(std::errc::operation_canceled));
    }

    // Throwing constructor
    explicit basic_service_server(executor_type ex, service_info info,
                                  service_options opts = {},
                                  policy_socket_options_t<P> sock_opts = {},
                                  mdns_options mdns_opts = {})
        : base(ex, sock_opts, std::move(mdns_opts))
        , m_response_timer(ex)
        , m_delay_timer(ex)
        , m_tc_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
        , m_binding(detail::extract_interface_binding(sock_opts))
    {
        if(auto ec = detail::validate_server_options(m_info, m_opts, this->m_mdns_opts))
            throw std::system_error(ec, "basic_service_server options");
    }

    // Non-throwing constructor
    basic_service_server(executor_type ex, service_info info,
                         service_options opts, policy_socket_options_t<P> sock_opts,
                         mdns_options mdns_opts, std::error_code &ec)
        : base(ex, sock_opts, std::move(mdns_opts), ec)
        , m_response_timer(ex)
        , m_delay_timer(ex)
        , m_tc_timer(ex)
        , m_info(std::move(info))
        , m_opts(std::move(opts))
        , m_rng(std::random_device{}())
        , m_binding(detail::extract_interface_binding(sock_opts))
    {
        if(!ec)
            ec = detail::validate_server_options(m_info, m_opts, this->m_mdns_opts);
    }

    // async_start() -- begins the probe -> announce -> live sequence.
    // on_ready fires after probe+announce completes (success) or on permanent
    // probe failure. on_done fires after teardown completes.
    // One-shot: a second call completes on_ready with operation_in_progress;
    // a call after stop() completes on_ready with invalid_argument. Misuse is
    // detected through atomic flags only (callable from any thread) and the
    // misuse completion is posted to the executor, never invoked inline.
    void async_start(completion_handler on_ready = {}, completion_handler on_done = {})
    {
        if(this->m_stopped.load(std::memory_order_acquire))
        {
            if(on_ready)
                this->post_guarded([h = std::move(on_ready)]() mutable
                {
                    h(std::make_error_code(std::errc::invalid_argument));
                });
            return;
        }
        if(m_started.exchange(true, std::memory_order_acq_rel))
        {
            if(on_ready)
                this->post_guarded([h = std::move(on_ready)]() mutable
                {
                    h(std::make_error_code(std::errc::operation_in_progress));
                });
            return;
        }
        if(on_ready)
            m_on_ready = std::move(on_ready);
        if(on_done)
            m_on_completion = std::move(on_done);
        do_start();
    }

    // stop() -- idempotent; posts teardown to the executor thread, ensuring all
    // state mutations and the goodbye build and send happen on the executor
    // (no cross-thread data race: m_info is written on the executor by
    // update_service_info and conflict renames, so it must not be read on the
    // caller thread). The posted teardown sends the goodbye only when the
    // server was announcing or live (RFC 6762 section 10.1); consequently a
    // goodbye goes out only if the executor runs after stop().
    void stop()
    {
        if(this->m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        auto guard = std::weak_ptr<bool>(this->m_alive);
        P::post(this->m_executor, [this, guard]()
        {
            if(!guard.lock()) return;

            if(m_opts.send_goodbye
               && (m_pa_state.state == server_state::live
                   || m_pa_state.state == server_state::announcing))
            {
                auto goodbye = build_goodbye_packet();
                if(!goodbye.empty())
                {
                    std::error_code ec;
                    this->m_socket.send(this->multicast_endpoint(),
                                        std::span<const std::byte>(goodbye), ec);
                    report_error(ec, "goodbye send");
                }
            }

            if(m_pa_state.state == server_state::probing || m_pa_state.state == server_state::announcing)
            {
                if(auto h = std::exchange(m_on_ready, nullptr); h)
                    h(std::make_error_code(std::errc::operation_canceled));
            }

            teardown();

            if(auto h = std::exchange(m_on_completion, nullptr); h)
                h(std::error_code{});
        });
    }

    // update_service_info() -- posts a service info replacement to the event loop.
    // When service_name and hostname are unchanged, an announcement burst is
    // sent (RFC 6762 section 8.4). A changed service_name or hostname is a new
    // record set and re-enters probing first (RFC 6762 section 8.1).
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
            bool renamed = info.service_name != m_info.service_name
                        || info.hostname != m_info.hostname;
            m_info = std::move(info);
            resolve_auto_addresses();
            if(renamed)
            {
                start_probing();
                return;
            }
            m_pa_state.announce_count = 0;
            send_update_announce();
        });
    }

    // Server-specific timer accessors:
    const timer_type &timer() const noexcept { return m_response_timer; }
    timer_type &timer() noexcept { return m_response_timer; }
    const timer_type &delay_timer() const noexcept { return m_delay_timer; }
    timer_type &delay_timer() noexcept { return m_delay_timer; }
    const timer_type &tc_timer() const noexcept { return m_tc_timer; }
    timer_type &tc_timer() noexcept { return m_tc_timer; }
    const timer_type &recv_timer() const noexcept { return base::timer(); }
    timer_type &recv_timer() noexcept { return base::timer(); }

private:
    // -------------------------------------------------------------------------
    // Lifecycle: start, probe, announce
    // -------------------------------------------------------------------------

    void do_start()
    {
        resolve_auto_addresses();

        this->m_loop = std::make_unique<detail::recv_loop<P>>(
            this->m_socket,
            this->m_timer,
            detail::infinite_silence_timeout, // run until stop()
            [this](const recv_metadata &meta, std::span<std::byte> data) -> bool
            {
                on_packet(meta.sender, data);
                return true;
            },
            []()
            {
                // no-op on silence
            },
            this->m_mdns_opts.receive_ttl_minimum,
            this->m_mdns_opts.unknown_ttl_policy,
            [this](std::error_code ec)
            {
                report_error(ec, "receive");
            });

        start_probing();
        this->m_loop->start();
    }

    void start_probing()
    {
        detail::begin_probing(m_pa_state);
        m_pending.reset();
        m_dup_suppression.reset();

        // Random delay [0, probe_initial_delay_max] before the first probe
        // (RFC 6762 section 8.1). After 15 conflicts within 10 s, every probe
        // attempt waits at least 5 s instead (RFC 6762 section 8.1).
        std::chrono::milliseconds delay;
        if(m_rate_limiter.throttled())
        {
            delay = std::chrono::duration_cast<std::chrono::milliseconds>(
                detail::probe_rate_limiter<clock_type>::probe_delay);
        }
        else
        {
            std::uniform_int_distribution<std::chrono::milliseconds::rep> dist(
                0, m_opts.probe_initial_delay_max.count());
            delay = std::chrono::milliseconds(dist(m_rng));
        }
        m_response_timer.expires_after(delay);
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
        if(probe.empty())
        {
            // Name encoding failed (label > 63 or name > 255 bytes) — the
            // record set can never be announced; abort startup.
            abort_startup(std::make_error_code(std::errc::invalid_argument));
            return;
        }

        std::error_code ec;
        this->m_socket.send(this->multicast_endpoint(), std::span<const std::byte>(probe), ec);
        report_error(ec, "probe send");

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
            m_pa_state.state = server_state::live;
            if(auto h = std::exchange(m_on_ready, nullptr); h)
                h(std::error_code{});
        }
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

    // RFC 6762 §6.2: advertised addresses must be valid on the announcing
    // link. When service_info::auto_address is set (service_info::make()),
    // fill the unset address fields from the interface the socket is bound to
    // (socket_options interface_index / interface_name / interface_address),
    // or, unbound, from the lowest-index non-loopback running interface per
    // family (see detail::resolve_advertised_addresses). Runs at async_start
    // and after every update_service_info.
    void resolve_auto_addresses()
    {
        if(!m_info.auto_address)
            return;
        std::error_code ec;
        auto interfaces = enumerate_interfaces(ec);
        if(ec)
        {
            report_error(ec, "interface enumeration");
            return;
        }
        detail::resolve_advertised_addresses(interfaces, m_binding, m_info);
    }

    // Validates address fields in m_info against the encode functions and invokes
    // the error handler for any that fail. Called before building DNS responses.
    void validate_addresses()
    {
        if(m_info.address_ipv4.has_value())
        {
            auto enc = detail::encode_ipv4(*m_info.address_ipv4);
            if(!enc.has_value())
                report_error(make_error_code(enc.error()),
                             "invalid IPv4 address: " + *m_info.address_ipv4);
        }
        if(m_info.address_ipv6.has_value())
        {
            auto enc = detail::encode_ipv6(*m_info.address_ipv6);
            if(!enc.has_value())
                report_error(make_error_code(enc.error()),
                             "invalid IPv6 address: " + *m_info.address_ipv6);
        }
    }

    // Sends an unsolicited announcement with all records (PTR, SRV, TXT, A/AAAA)
    // to the multicast group. RFC 6762 section 8.4.
    void send_announcement()
    {
        validate_addresses();
        auto response = detail::build_dns_response(m_info, dns_type::any, m_opts);
        if(!response.empty())
        {
            send_to(response_mode::multicast, {}, std::span<const std::byte>(response), "announcement send");
            m_last_multicast = clock_type::now();
        }

        if(m_opts.respond_to_meta_queries)
        {
            uint32_t ttl = static_cast<uint32_t>(m_opts.fallback_record_ttl.count());
            auto pkt = detail::build_meta_query_response(m_info, ttl);
            if(!pkt.empty())
                send_to(response_mode::multicast, {}, std::span<const std::byte>(pkt), "announcement send");
        }

        if(m_opts.announce_subtypes)
        {
            uint32_t ttl = static_cast<uint32_t>(m_opts.fallback_record_ttl.count());
            for(const auto &sub : m_info.subtypes)
            {
                auto pkt = detail::build_subtype_response(sub, m_info, ttl);
                if(!pkt.empty())
                    send_to(response_mode::multicast, {}, std::span<const std::byte>(pkt), "announcement send");
            }
        }
    }

    // -------------------------------------------------------------------------
    // Conflict handling
    // -------------------------------------------------------------------------

    void handle_conflict(conflict_type ct = conflict_type::name_conflict)
    {
        m_response_timer.cancel();

        if(ct == conflict_type::tiebreak_deferred)
        {
            if(m_opts.on_conflict)
                (void)m_opts.on_conflict(m_info.service_name, m_pa_state.conflict_attempt, ct);
            defer_and_reprobe();
            return;
        }

        m_rate_limiter.record_conflict();

        if(m_opts.on_conflict)
        {
            auto new_name = m_opts.on_conflict(m_info.service_name, m_pa_state.conflict_attempt, ct);
            if(new_name.has_value())
            {
                m_info.service_name = std::move(*new_name);
                ++m_pa_state.conflict_attempt;
                start_probing();
                return;
            }
        }

        // No callback or callback gave up -- permanent failure, full teardown
        abort_startup(mdns_error::probe_conflict);
    }

    void defer_and_reprobe()
    {
        m_response_timer.expires_after(m_opts.probe_defer_delay);
        m_response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || this->m_stopped.load(std::memory_order_acquire)) return;
            start_probing();
        });
    }

    // Permanent startup failure: fire on_ready with the failure reason, run
    // the full teardown, then fire on_done with success. Runs on the executor.
    void abort_startup(std::error_code reason)
    {
        if(this->m_stopped.exchange(true, std::memory_order_acq_rel))
            return;

        if(auto h = std::exchange(m_on_ready, nullptr); h)
            h(reason);

        teardown();

        if(auto h = std::exchange(m_on_completion, nullptr); h)
            h(std::error_code{});
    }

    void teardown()
    {
        m_pa_state.state = server_state::stopped;
        m_pending.reset();
        m_response_timer.cancel();
        m_delay_timer.cancel();
        m_tc_timer.cancel();
        m_tc_acc.clear();
        m_tc_timer_armed = false;

        if(this->m_loop)
            this->m_loop->stop();
    }

    // -------------------------------------------------------------------------
    // Goodbye
    // -------------------------------------------------------------------------

    std::vector<std::byte> build_goodbye_packet() const
    {
        service_options goodbye_opts;
        goodbye_opts.ptr_ttl    = std::chrono::seconds{0};
        goodbye_opts.srv_ttl    = std::chrono::seconds{0};
        goodbye_opts.txt_ttl    = std::chrono::seconds{0};
        goodbye_opts.a_ttl      = std::chrono::seconds{0};
        goodbye_opts.aaaa_ttl   = std::chrono::seconds{0};
        goodbye_opts.fallback_record_ttl = std::chrono::seconds{0};
        return detail::build_dns_response(m_info, dns_type::any, goodbye_opts);
    }

    // -------------------------------------------------------------------------
    // Packet dispatch
    // -------------------------------------------------------------------------

    void on_packet(const endpoint &sender, std::span<std::byte> data)
    {
        if(this->m_stopped.load(std::memory_order_acquire))
            return;

        if(m_pa_state.state == server_state::probing)
        {
            handle_probing_packet(sender, data);
            return;
        }

        if(m_pa_state.state != server_state::live && m_pa_state.state != server_state::announcing)
            return;

        if(data.size() < 12)
            return;

        uint16_t flags = detail::read_u16_be(data.data() + 2);
        bool is_response = (flags & 0x8000) != 0;
        bool tc_set = (flags & 0x0200) != 0;
        uint16_t qdcount = detail::read_u16_be(data.data() + 4);
        auto cdata = std::span<const std::byte>(data.data(), data.size());

        if(is_response)
        {
            handle_incoming_response(cdata);
            return;
        }

        if(m_pa_state.state != server_state::live)
            return; // queries are not answered while announcing

        if(tc_set)
        {
            handle_tc_query(sender, cdata);
            return;
        }

        // RFC 6762 section 7.2: a compliant querier's FINAL continuation packet
        // has TC clear and no questions; merge its known answers into the
        // pending TC state before the suppression decision.
        if(qdcount == 0 && m_tc_acc.has_pending(sender))
        {
            m_tc_acc.accumulate(sender, parse_answer_records(cdata), this->m_mdns_opts.tc_wait_min);
            return;
        }

        handle_normal_query(sender, cdata);
    }

    // During probing: check for conflicting responses and simultaneous probes.
    void handle_probing_packet(const endpoint &sender, std::span<std::byte> data)
    {
        (void)sender;
        if(data.size() < 12)
            return;

        uint16_t flags = detail::read_u16_be(data.data() + 2);
        auto cdata = std::span<const std::byte>(data.data(), data.size());

        if(flags & 0x8000)
        {
            // Response from an authoritative owner (QR=1)
            if(response_conflicts(data))
                handle_conflict(conflict_type::name_conflict);
            return;
        }

        // Query -- check for simultaneous probe (RFC 6762 section 8.2)
        uint16_t nscount = detail::read_u16_be(data.data() + 8);
        if(nscount == 0 || !response_conflicts(data))
            return;

        // RFC 6762 section 8.2.1 tiebreaking over the full proposed record
        // sets, compared in DNS uncompressed form ordered by class, type,
        // rdata. Our own looped-back probe carries an identical record set
        // and compares equal — an exact tie is NOT a conflict.
        auto theirs = detail::extract_authority_records(cdata);
        if(theirs.empty())
        {
            handle_conflict(conflict_type::name_conflict);
            return;
        }

        int32_t cmp = detail::compare_record_sets(build_our_tiebreak_records(), std::move(theirs));
        if(cmp < 0)
        {
            detail::begin_probing(m_pa_state);
            handle_conflict(conflict_type::tiebreak_deferred);
        }
    }

    // RFC 6762 sections 9 and 7.4: incoming responses while announcing or live
    // are screened for conflicts (our unique name, different rdata) and, when a
    // response delay window is pending, observed for duplicate suppression.
    void handle_incoming_response(std::span<const std::byte> cdata)
    {
        auto records = parse_answer_records(cdata);

        for(const auto &rec : records)
        {
            if(detail::record_conflicts_ours(rec, m_info))
            {
                handle_conflict(conflict_type::name_conflict);
                return;
            }
        }

        if(!m_pending.armed)
            return;

        for(const auto &rec : records)
        {
            uint32_t observed_ttl = std::visit([](const auto &r) { return r.ttl; }, rec);
            m_dup_suppression.observe(rec, observed_ttl);
        }
    }

    // RFC 6762 section 7.2: TC bit set -- accumulate known answers per source
    // and defer processing until the per-source deadline passes.
    void handle_tc_query(const endpoint &sender, std::span<const std::byte> cdata)
    {
        std::uniform_int_distribution<std::chrono::milliseconds::rep> dist(
            this->m_mdns_opts.tc_wait_min.count(),
            this->m_mdns_opts.tc_wait_max.count());
        auto tc_wait = std::chrono::milliseconds(dist(m_rng));

        m_tc_acc.accumulate(sender, parse_answer_records(cdata), tc_wait);
        arm_tc_timer();
    }

    // Arms the single TC timer for the EARLIEST pending deadline; sources
    // whose deadlines pass are all drained when it fires, then the timer is
    // re-armed for the next pending deadline.
    void arm_tc_timer()
    {
        auto next = m_tc_acc.next_deadline();
        if(!next.has_value())
        {
            m_tc_timer_armed = false;
            return;
        }
        if(m_tc_timer_armed && *next >= m_tc_deadline)
            return;

        m_tc_timer_armed = true;
        m_tc_deadline = *next;

        auto now = clock_type::now();
        auto delay = *next > now
            ? std::chrono::ceil<std::chrono::milliseconds>(*next - now)
            : std::chrono::milliseconds::zero();
        m_tc_timer.expires_after(delay);
        m_tc_timer.async_wait([this](std::error_code ec)
        {
            if(ec || this->m_stopped.load(std::memory_order_acquire))
                return;
            on_tc_timer_expired();
        });
    }

    void on_tc_timer_expired()
    {
        m_tc_timer_armed = false;
        if(m_pa_state.state != server_state::live)
            return;

        // Coarse timers may fire marginally before the stored deadline; drain
        // everything due at the armed deadline.
        auto now = (std::max)(clock_type::now(), m_tc_deadline);
        for(auto &[sender, merged] : m_tc_acc.take_expired(now))
            process_tc_known_answers(sender, merged);

        arm_tc_timer();
    }

    void process_tc_known_answers(const endpoint &sender,
                                  const std::vector<mdns_record_variant> &merged)
    {
        if(m_opts.on_tc_continuation)
            m_opts.on_tc_continuation(sender, merged.size());

        auto plan = detail::plan_all_answers(m_info);
        if(m_opts.suppress_known_answers)
        {
            auto th = detail::make_ka_thresholds(m_opts, this->m_mdns_opts.tc_suppression_fraction);
            auto mask = detail::suppress_from_records(merged, m_info, th);
            detail::apply_suppression(plan, mask);
        }
        if(plan.empty())
            return;

        schedule_multicast_response(plan);
    }

    // Normal (non-TC) query processing.
    void handle_normal_query(const endpoint &sender, std::span<const std::byte> cdata)
    {
        // RFC 6762 section 6.7: legacy unicast detection.
        if(m_opts.respond_to_legacy_unicast && sender.port != 0 && sender.port != 5353)
        {
            handle_legacy_unicast(sender, cdata);
            return;
        }

        auto qmr = detail::match_queries(cdata, m_info, m_opts);
        if(!qmr.any_matched && !qmr.meta_matched && qmr.matched_subtype.empty())
            return;

        detail::suppression_mask suppression;
        if(m_opts.suppress_known_answers && qmr.any_matched)
        {
            auto th = detail::make_ka_thresholds(m_opts, this->m_mdns_opts.ka_suppression_fraction);
            suppression = detail::parse_known_answers(cdata, qmr.offset_after_questions, m_info, th);
        }

        if(m_opts.on_query && qmr.any_matched)
            m_opts.on_query(sender, qmr.accumulated_qtype, qmr.mode);

        send_meta_and_subtype_responses(qmr, sender);

        if(!qmr.any_matched)
            return;

        auto plan = detail::plan_answers(qmr.matched, m_info);
        if(m_opts.suppress_known_answers)
            detail::apply_suppression(plan, suppression);
        if(plan.empty())
            return;

        if(qmr.mode == response_mode::unicast)
        {
            // RFC 6762 section 5.4: answer a QU question via multicast instead
            // when the records have not been multicast within the last quarter
            // of their TTL.
            if(!detail::qu_requires_multicast(m_last_multicast, clock_type::now(),
                                              detail::min_planned_ttl(plan, m_opts)))
            {
                auto pkt = detail::build_answer_response(m_info, plan, m_opts);
                if(!pkt.empty())
                    send_to(response_mode::unicast, sender, std::span<const std::byte>(pkt), "response send");
                return;
            }
        }

        // RFC 6762 section 6: responses carrying only unique, probe-verified
        // records may go immediately; shared records (PTR) take the 20-120 ms
        // random delay, as does anything merged into a pending window.
        if(!m_pending.armed && !plan.has_shared())
        {
            send_multicast_plan(plan);
            return;
        }

        schedule_multicast_response(plan);
    }

    // Respond to queries from non-5353 ports per RFC 6762 section 6.7: the
    // response repeats the query ID and question, never sets the cache-flush
    // bit, and caps TTLs at legacy_unicast_ttl.
    void handle_legacy_unicast(const endpoint &sender, std::span<const std::byte> cdata)
    {
        auto qmr = detail::match_queries(cdata, m_info, m_opts);
        if(!qmr.any_matched)
            return;

        auto plan = detail::plan_answers(qmr.matched, m_info);
        if(!plan.has_answers())
            return;

        auto [questions, qdcount] = detail::rebuild_question_section(cdata);

        detail::response_header_options hdr;
        hdr.id = qmr.query_id;
        hdr.cache_flush = false;
        hdr.include_nsec = false;
        hdr.ttl_cap = static_cast<uint32_t>(this->m_mdns_opts.legacy_unicast_ttl.count());
        hdr.questions = std::span<const std::byte>(questions);
        hdr.qdcount = qdcount;

        auto pkt = detail::build_answer_response(m_info, plan, m_opts, hdr);
        if(!pkt.empty())
            send_to(response_mode::unicast, sender, std::span<const std::byte>(pkt), "legacy unicast response");
    }

    void send_meta_and_subtype_responses(const detail::query_match_result &qmr,
                                          const endpoint &sender)
    {
        if(qmr.meta_matched)
        {
            uint32_t meta_ttl = static_cast<uint32_t>(m_opts.fallback_record_ttl.count());
            auto pkt = detail::build_meta_query_response(m_info, meta_ttl);
            send_to(qmr.mode, sender, std::span<const std::byte>(pkt), "meta-query response send");
        }

        if(!qmr.matched_subtype.empty())
        {
            uint32_t sub_ttl = static_cast<uint32_t>(m_opts.fallback_record_ttl.count());
            auto pkt = detail::build_subtype_response(qmr.matched_subtype, m_info, sub_ttl);
            send_to(qmr.mode, sender, std::span<const std::byte>(pkt), "subtype response send");
        }
    }

    // -------------------------------------------------------------------------
    // Multicast response scheduling
    // -------------------------------------------------------------------------

    // Scheduled RFC 6762 section 6 delayed responses run on m_delay_timer,
    // never on m_response_timer: the probe/announce duties of
    // m_response_timer (initial probe delay, probe interval, announce
    // interval, update-announce interval, defer-reprobe) belong to mutually
    // exclusive m_pa_state states, but an update_service_info announce burst
    // can overlap a pending delayed response while live -- a shared timer
    // would let the announce expires_after cancel the scheduled response.
    void schedule_multicast_response(const detail::answer_plan &plan)
    {
        bool was_armed = m_pending.armed;
        m_pending.merge(plan);
        if(was_armed)
            return;

        std::uniform_int_distribution<std::chrono::milliseconds::rep> dist(
            this->m_mdns_opts.response_delay_min.count(),
            this->m_mdns_opts.response_delay_max.count());
        m_delay_timer.expires_after(std::chrono::milliseconds(dist(m_rng)));
        m_delay_timer.async_wait([this](std::error_code ec)
        {
            if(ec || this->m_stopped.load(std::memory_order_acquire))
                return;
            if(m_pa_state.state != server_state::live)
                return;
            fire_pending_response();
        });
    }

    void fire_pending_response()
    {
        auto plan = m_pending.plan;
        m_pending.reset();

        apply_duplicate_suppression(plan);
        m_dup_suppression.reset();

        if(plan.empty())
            return;

        send_multicast_plan(plan);
    }

    void send_multicast_plan(const detail::answer_plan &plan)
    {
        auto response = detail::build_answer_response(m_info, plan, m_opts);
        if(response.empty())
            return;
        send_to(response_mode::multicast, {}, std::span<const std::byte>(response), "response send");
        m_last_multicast = clock_type::now();
    }

    // RFC 6762 section 7.4: suppress record types another responder already
    // multicast (with TTL at least ours) during the pending delay window.
    void apply_duplicate_suppression(detail::answer_plan &plan)
    {
        if(m_dup_suppression.empty())
            return;

        auto candidate_pkt = detail::build_dns_response(m_info, dns_type::any, m_opts);
        std::vector<mdns_record_variant> candidates;
        detail::walk_dns_frame(
            std::span<const std::byte>(candidate_pkt.data(), candidate_pkt.size()),
            endpoint{},
            [&](mdns_record_variant rv) { candidates.push_back(std::move(rv)); });

        detail::suppression_mask mask;
        for(const auto &rec : candidates)
        {
            uint32_t our_ttl = std::visit([](const auto &r) { return r.ttl; }, rec);
            if(m_dup_suppression.is_suppressed(rec, our_ttl))
                detail::mark_suppressed_type(mask, rec);
        }
        detail::apply_suppression(plan, mask);
    }

    // -------------------------------------------------------------------------
    // Wire helpers
    // -------------------------------------------------------------------------

    void report_error(std::error_code ec, std::string_view context)
    {
        if(ec && m_opts.on_error)
            m_opts.on_error(ec, context);
    }

    void send_to(response_mode mode, const endpoint &sender,
                  std::span<const std::byte> packet, std::string_view context)
    {
        std::error_code ec;
        if(mode == response_mode::unicast)
            this->m_socket.send(sender, packet, ec);
        else
            this->m_socket.send(this->multicast_endpoint(), packet, ec);
        report_error(ec, context);
    }

    std::vector<mdns_record_variant> parse_answer_records(std::span<const std::byte> data)
    {
        std::vector<mdns_record_variant> records;
        detail::walk_dns_frame(data, endpoint{}, [&](mdns_record_variant rv)
        {
            records.push_back(std::move(rv));
        });
        return records;
    }

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

    std::vector<detail::tiebreak_record> build_our_tiebreak_records() const
    {
        std::vector<detail::tiebreak_record> records;
        for(auto &rec : detail::build_proposed_records(m_info))
            records.push_back(detail::tiebreak_record{
                detail::to_underlying(dns_class::in),
                detail::to_underlying(rec.rtype),
                std::move(rec.rdata)});
        return records;
    }

    // -------------------------------------------------------------------------
    // Data members -- fundamental types first, then abstract types;
    // within each group: ascending by type length, then name length, then alpha.
    // -------------------------------------------------------------------------

    // NOTE: the timers cannot be reordered below m_info/m_opts because they
    // must be initialized from the executor before the service_info and
    // service_options parameters are moved from in the constructor init list.

    timer_type m_response_timer;
    timer_type m_delay_timer;
    timer_type m_tc_timer;
    service_info m_info;
    service_options m_opts;
    completion_handler m_on_ready;
    completion_handler m_on_completion;
    std::mt19937 m_rng;
    detail::interface_binding m_binding;
    detail::probe_announce_state m_pa_state;
    detail::pending_response m_pending;
    detail::tc_accumulator<clock_type> m_tc_acc;
    detail::duplicate_suppression_state m_dup_suppression;
    detail::probe_rate_limiter<clock_type> m_rate_limiter;
    clock_type::time_point m_tc_deadline{};
    clock_type::time_point m_last_multicast{};
    std::atomic<bool> m_started{false};
    bool m_tc_timer_armed{false};
};

}

#endif

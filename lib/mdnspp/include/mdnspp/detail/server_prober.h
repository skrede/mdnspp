#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_PROBER_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_PROBER_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/server_context.h"
#include "mdnspp/detail/server_announcer.h"
#include "mdnspp/detail/server_conflicts.h"
#include "mdnspp/detail/server_multicast.h"
#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"

#include <span>
#include <chrono>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <system_error>

namespace mdnspp::detail {

// Probing and conflict handling of RFC 6762 sections 8.1, 8.2 and 9 on the response timer. abort_cb reports
// a permanent startup failure.
template <policy_like P>
class server_prober
{
    using clock_type = std::chrono::steady_clock;

public:
    using abort_callback = move_only_function<void(std::error_code)>;

    server_prober(server_context<P> &ctx, server_multicast<P> &multicast, server_announcer<P> &announcer,
                  abort_callback abort_cb)
        : m_ctx(ctx)
        , m_abort_cb(std::move(abort_cb))
        , m_announcer(announcer)
        , m_multicast(multicast)
        , m_rate_limiter()
    {
    }

    void start_probing()
    {
        begin_probing(m_ctx.pa_state);
        m_ctx.siblings.publish(m_ctx.info);
        m_multicast.reset();
        m_ctx.response_timer.expires_after(first_probe_delay());
        m_ctx.response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_ctx.pa_state.state != server_state::probing) return;
            if(m_ctx.stopped()) return;
            send_probe();
        });
    }

    void on_probing_packet(std::span<const std::byte> data)
    {
        switch(classify_probing_packet(data, m_ctx.info, m_ctx.siblings))
        {
        case probe_verdict::conflict:
            handle_conflict(conflict_type::name_conflict);
            break;
        case probe_verdict::deferred:
            begin_probing(m_ctx.pa_state);
            handle_conflict(conflict_type::tiebreak_deferred);
            break;
        case probe_verdict::none:
            break;
        }
    }

    // Returns whether the records held a conflict, which has then been handled.
    bool screen(const std::vector<mdns_record_variant> &records)
    {
        if(!live_conflict(records, m_ctx.info, m_ctx.siblings))
            return false;
        handle_conflict(conflict_type::name_conflict);
        return true;
    }

private:
    server_context<P> &m_ctx;
    abort_callback m_abort_cb;
    server_announcer<P> &m_announcer;
    server_multicast<P> &m_multicast;
    probe_rate_limiter<clock_type> m_rate_limiter;

    // RFC 6762 section 8.1: a random delay in [0, probe_initial_delay_max] before the first probe; after
    // 15 conflicts within 10 s every probe attempt waits at least 5 s instead.
    std::chrono::milliseconds first_probe_delay()
    {
        if(m_rate_limiter.throttled())
            return std::chrono::duration_cast<std::chrono::milliseconds>(probe_rate_limiter<clock_type>::probe_delay);
        std::uniform_int_distribution<std::chrono::milliseconds::rep> dist(
            0, m_ctx.opts.probe_initial_delay_max.count());
        return std::chrono::milliseconds(dist(m_ctx.rng));
    }

    void send_probe()
    {
        if(m_ctx.pa_state.state != server_state::probing) return;
        if(m_ctx.stopped()) return;

        auto probe = build_probe_query(m_ctx.info, wire_ttl(m_ctx.opts.probe_authority_ttl));
        if(probe.empty())
        {
            // An unencodable name (label over 63 or name over 255 bytes) can never be announced.
            m_abort_cb(std::make_error_code(std::errc::invalid_argument));
            return;
        }

        m_ctx.send_to(response_mode::multicast, {}, probe, "probe send");
        schedule_after_probe(advance_probe(m_ctx.pa_state, m_ctx.opts.probe_count));
    }

    void schedule_after_probe(bool more)
    {
        m_ctx.response_timer.expires_after(m_ctx.opts.probe_interval);
        m_ctx.response_timer.async_wait([this, more](std::error_code wait_ec)
        {
            if(wait_ec || m_ctx.pa_state.state != server_state::probing) return;
            if(m_ctx.stopped()) return;
            if(more)
                send_probe();
            else
                m_announcer.start();
        });
    }

    void handle_conflict(conflict_type ct)
    {
        m_ctx.response_timer.cancel();
        if(ct == conflict_type::tiebreak_deferred)
        {
            if(m_ctx.opts.on_conflict)
                (void)m_ctx.opts.on_conflict(m_ctx.info.service_name, m_ctx.pa_state.conflict_attempt, ct);
            defer_and_reprobe();
            return;
        }
        m_rate_limiter.record_conflict();
        if(!rename(ct))
            m_abort_cb(mdns_error::probe_conflict);
    }

    // Returns whether on_conflict supplied a replacement name, with which probing restarts.
    bool rename(conflict_type ct)
    {
        if(!m_ctx.opts.on_conflict)
            return false;
        auto new_name = m_ctx.opts.on_conflict(m_ctx.info.service_name, m_ctx.pa_state.conflict_attempt, ct);
        if(!new_name.has_value())
            return false;
        m_ctx.info.service_name = std::move(*new_name);
        ++m_ctx.pa_state.conflict_attempt;
        start_probing();
        return true;
    }

    void defer_and_reprobe()
    {
        m_ctx.response_timer.expires_after(m_ctx.opts.probe_defer_delay);
        m_ctx.response_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_ctx.stopped()) return;
            start_probing();
        });
    }
};

}

#endif

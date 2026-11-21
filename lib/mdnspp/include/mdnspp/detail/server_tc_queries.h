#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_TC_QUERIES_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_TC_QUERIES_H

#include "mdnspp/detail/server_context.h"
#include "mdnspp/detail/tc_accumulator.h"
#include "mdnspp/detail/server_multicast.h"
#include "mdnspp/detail/server_answer_plan.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <span>
#include <chrono>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <system_error>

namespace mdnspp::detail {

// RFC 6762 section 7.2: known answers of truncated queries accumulate per source until that source's
// deadline. One timer is armed for the earliest deadline; every source due when it fires is drained,
// then the timer is re-armed for the next one.
template <policy_like P>
class server_tc_queries
{
    using clock_type = std::chrono::steady_clock;

public:
    server_tc_queries(server_context<P> &ctx, server_multicast<P> &multicast)
        : m_armed(false)
        , m_ctx(ctx)
        , m_multicast(multicast)
        , m_deadline()
        , m_accumulator()
    {
    }

    void accumulate(const endpoint &sender, std::span<const std::byte> cdata)
    {
        std::uniform_int_distribution<std::chrono::milliseconds::rep> dist(m_ctx.mdns_opts.tc_wait_min.count(),
                                                                           m_ctx.mdns_opts.tc_wait_max.count());
        auto tc_wait = std::chrono::milliseconds(dist(m_ctx.rng));

        m_accumulator.accumulate(sender, parse_answer_records(cdata), tc_wait);
        arm();
    }

    // A compliant querier's final continuation packet has TC clear and no questions; its known answers
    // join the pending set before the suppression decision.
    bool merge_final(const endpoint &sender, std::span<const std::byte> cdata, uint16_t qdcount)
    {
        if(qdcount != 0 || !m_accumulator.has_pending(sender))
            return false;
        m_accumulator.accumulate(sender, parse_answer_records(cdata), m_ctx.mdns_opts.tc_wait_min);
        return true;
    }

    void clear()
    {
        m_accumulator.clear();
        m_armed = false;
    }

private:
    bool m_armed;
    server_context<P> &m_ctx;
    server_multicast<P> &m_multicast;
    clock_type::time_point m_deadline;
    tc_accumulator<clock_type> m_accumulator;

    void arm()
    {
        auto next = m_accumulator.next_deadline();
        if(!next.has_value())
        {
            m_armed = false;
            return;
        }
        if(m_armed && *next >= m_deadline)
            return;

        m_armed = true;
        m_deadline = *next;

        auto now = clock_type::now();
        auto delay = *next > now ? std::chrono::ceil<std::chrono::milliseconds>(*next - now)
                                 : std::chrono::milliseconds::zero();
        m_ctx.tc_timer.expires_after(delay);
        m_ctx.tc_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_ctx.stopped())
                return;
            on_expired();
        });
    }

    void on_expired()
    {
        m_armed = false;
        if(m_ctx.pa_state.state != server_state::live)
            return;

        // Coarse timers may fire marginally before the stored deadline, so everything due at the armed
        // deadline is drained.
        auto now = (std::max)(clock_type::now(), m_deadline);
        for(auto &[sender, merged] : m_accumulator.take_expired(now))
            process_known_answers(sender, merged);

        arm();
    }

    void process_known_answers(const endpoint &sender, const std::vector<mdns_record_variant> &merged)
    {
        if(m_ctx.opts.on_tc_continuation)
            m_ctx.opts.on_tc_continuation(sender, merged.size());

        auto plan = plan_all_answers(m_ctx.info);
        if(m_ctx.opts.suppress_known_answers)
        {
            auto th = make_ka_thresholds(m_ctx.opts, m_ctx.mdns_opts.tc_suppression_fraction);
            auto mask = suppress_from_records(merged, m_ctx.info, th);
            apply_suppression(plan, mask);
        }
        if(plan.empty())
            return;

        m_multicast.schedule(plan);
    }
};

}

#endif

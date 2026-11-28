#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_RESPONDER_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_RESPONDER_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/server_context.h"
#include "mdnspp/detail/server_multicast.h"
#include "mdnspp/detail/server_answer_plan.h"
#include "mdnspp/detail/server_query_match.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/server_meta_response.h"
#include "mdnspp/detail/server_question_section.h"
#include "mdnspp/detail/server_response_aggregation.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"

#include <span>
#include <chrono>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

template <policy_like P>
class server_responder
{
    using clock_type = std::chrono::steady_clock;

public:
    server_responder(server_context<P> &ctx, server_multicast<P> &multicast)
        : m_ctx(ctx)
        , m_multicast(multicast)
    {
    }

    void answer(const endpoint &sender, std::span<const std::byte> cdata)
    {
        // RFC 6762 section 6.7: legacy unicast detection, against the configured multicast port in place of 5353.
        if(m_ctx.opts.respond_to_legacy_unicast && sender.port != m_ctx.multicast_port())
        {
            answer_legacy_unicast(sender, cdata);
            return;
        }

        auto qmr = match_queries(cdata, m_ctx.info, m_ctx.opts);
        if(!qmr.any_matched && !qmr.meta_matched && qmr.matched_subtype.empty())
            return;

        auto suppression = known_answer_suppression(qmr, cdata);
        if(m_ctx.opts.on_query && qmr.any_matched)
            m_ctx.opts.on_query(sender, qmr.accumulated_qtype, qmr.mode);

        send_meta_and_subtype_responses(qmr, sender);

        if(qmr.any_matched)
            send_answers(qmr, suppression, sender);
    }

private:
    server_context<P> &m_ctx;
    server_multicast<P> &m_multicast;

    suppression_mask known_answer_suppression(const query_match_result &qmr, std::span<const std::byte> cdata)
    {
        suppression_mask suppression;
        if(m_ctx.opts.suppress_known_answers && qmr.any_matched)
        {
            auto th = make_ka_thresholds(m_ctx.opts, m_ctx.mdns_opts.ka_suppression_fraction);
            suppression = parse_known_answers(cdata, qmr.offset_after_questions, m_ctx.info, th);
        }
        return suppression;
    }

    void send_answers(const query_match_result &qmr, const suppression_mask &suppression, const endpoint &sender)
    {
        auto plan = plan_answers(qmr.matched, m_ctx.info);
        if(m_ctx.opts.suppress_known_answers)
            apply_suppression(plan, suppression);
        if(plan.empty() || send_unicast(qmr, plan, sender))
            return;

        // RFC 6762 section 6: responses carrying only unique, probe-verified records may go immediately;
        // shared records (PTR) take the 20-120 ms random delay, as does anything merged into a pending window.
        if(!m_multicast.pending() && !plan.has_shared())
        {
            m_multicast.send_plan(plan);
            return;
        }
        m_multicast.schedule(plan);
    }

    // RFC 6762 section 5.4: a QU question is answered via multicast instead when the records have not been
    // multicast within the last quarter of their TTL. Returns whether the question was answered by unicast.
    bool send_unicast(const query_match_result &qmr, const answer_plan &plan, const endpoint &sender)
    {
        if(qmr.mode != response_mode::unicast
           || qu_requires_multicast(m_multicast.last_multicast(), clock_type::now(),
                                    min_planned_ttl(plan, m_ctx.opts)))
            return false;
        auto pkt = build_answer_response(m_ctx.info, plan, m_ctx.opts);
        if(!pkt.empty())
            m_ctx.send_to(response_mode::unicast, sender, pkt, "response send");
        return true;
    }

    // RFC 6762 section 6.7: the response repeats the query ID and the whole question section ("MUST repeat"), so a
    // query whose questions cannot all be repeated gets no reply; it never sets cache-flush and caps TTLs.
    void answer_legacy_unicast(const endpoint &sender, std::span<const std::byte> cdata)
    {
        auto qmr = match_queries(cdata, m_ctx.info, m_ctx.opts);
        if(!qmr.any_matched)
            return;

        auto plan = plan_answers(qmr.matched, m_ctx.info);
        if(!plan.has_answers())
            return;

        auto [questions, qdcount] = rebuild_question_section(cdata);
        if(qdcount == 0)
            return;

        response_header_options hdr;
        hdr.id = qmr.query_id;
        hdr.cache_flush = false;
        hdr.include_nsec = false;
        hdr.ttl_cap = wire_ttl(m_ctx.mdns_opts.legacy_unicast_ttl);
        hdr.questions = std::span<const std::byte>(questions);
        hdr.qdcount = qdcount;

        auto pkt = build_answer_response(m_ctx.info, plan, m_ctx.opts, hdr);
        if(!pkt.empty())
            m_ctx.send_to(response_mode::unicast, sender, pkt, "legacy unicast response");
    }

    void send_meta_and_subtype_responses(const query_match_result &qmr, const endpoint &sender)
    {
        if(qmr.meta_matched)
        {
            uint32_t meta_ttl = wire_ttl(m_ctx.opts.fallback_record_ttl);
            auto pkt = build_meta_query_response(m_ctx.info, meta_ttl);
            m_ctx.send_to(qmr.mode, sender, pkt, "meta-query response send");
        }

        if(!qmr.matched_subtype.empty())
        {
            uint32_t sub_ttl = wire_ttl(m_ctx.opts.fallback_record_ttl);
            auto pkt = build_subtype_response(qmr.matched_subtype, m_ctx.info, sub_ttl);
            m_ctx.send_to(qmr.mode, sender, pkt, "subtype response send");
        }
    }
};

}

#endif

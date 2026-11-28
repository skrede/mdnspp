#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_MULTICAST_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_MULTICAST_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_frame.h"
#include "mdnspp/detail/dns_response.h"
#include "mdnspp/detail/server_context.h"
#include "mdnspp/detail/server_answer_plan.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/server_probe_announce.h"
#include "mdnspp/detail/server_response_aggregation.h"
#include "mdnspp/detail/duplicate_answer_suppression.h"

#include "mdnspp/policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include <span>
#include <chrono>
#include <random>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <variant>
#include <string_view>
#include <system_error>

namespace mdnspp::detail {

inline std::vector<std::byte> build_goodbye_packet(const service_info &info)
{
    service_options goodbye_opts;
    goodbye_opts.ptr_ttl = std::chrono::seconds{0};
    goodbye_opts.srv_ttl = std::chrono::seconds{0};
    goodbye_opts.txt_ttl = std::chrono::seconds{0};
    goodbye_opts.a_ttl = std::chrono::seconds{0};
    goodbye_opts.aaaa_ttl = std::chrono::seconds{0};
    goodbye_opts.fallback_record_ttl = std::chrono::seconds{0};
    return build_dns_response(info, dns_type::any, goodbye_opts);
}

template <policy_like P>
class server_multicast
{
    using clock_type = std::chrono::steady_clock;

public:
    explicit server_multicast(server_context<P> &ctx)
        : m_ctx(ctx)
        , m_pending()
        , m_last_multicast()
        , m_suppression()
    {
    }

    clock_type::time_point last_multicast() const noexcept { return m_last_multicast; }

    bool pending() const noexcept { return m_pending.armed; }

    void reset()
    {
        m_pending.reset();
        m_suppression.reset();
    }

    void drop_pending() { m_pending.reset(); }

    // RFC 6762 section 7.4: answers another responder multicasts during the delay window are recorded.
    void observe(const std::vector<mdns_record_variant> &records)
    {
        if(!m_pending.armed)
            return;
        for(const auto &rec : records)
        {
            uint32_t observed_ttl = std::visit([](const auto &r) { return r.ttl; }, rec);
            m_suppression.observe(rec, observed_ttl);
        }
    }

    void schedule(const answer_plan &plan)
    {
        bool was_armed = m_pending.armed;
        m_pending.merge(plan);
        if(was_armed)
            return;

        std::uniform_int_distribution<std::chrono::milliseconds::rep> dist(m_ctx.mdns_opts.response_delay_min.count(),
                                                                           m_ctx.mdns_opts.response_delay_max.count());
        m_ctx.delay_timer.expires_after(std::chrono::milliseconds(dist(m_ctx.rng)));
        m_ctx.delay_timer.async_wait([this](std::error_code ec)
        {
            if(ec || m_ctx.stopped())
                return;
            if(m_ctx.pa_state.state != server_state::live)
                return;
            fire_pending_response();
        });
    }

    void send_plan(const answer_plan &plan)
    {
        auto response = build_answer_response(m_ctx.info, plan, m_ctx.opts);
        if(!response.empty())
            send_stamped(response, "response send");
    }

    void send_stamped(std::span<const std::byte> packet, std::string_view context)
    {
        m_ctx.send_to(response_mode::multicast, {}, packet, context);
        m_last_multicast = clock_type::now();
    }

    // RFC 6762 section 10.1.
    void send_goodbye()
    {
        auto state = m_ctx.pa_state.state;
        if(!m_ctx.opts.send_goodbye || (state != server_state::live && state != server_state::announcing))
            return;
        auto goodbye = build_goodbye_packet(m_ctx.info);
        if(!goodbye.empty())
            m_ctx.send_to(response_mode::multicast, {}, goodbye, "goodbye send");
    }

private:
    server_context<P> &m_ctx;
    pending_response m_pending;
    clock_type::time_point m_last_multicast;
    duplicate_suppression_state m_suppression;

    void fire_pending_response()
    {
        auto plan = m_pending.plan;
        m_pending.reset();

        apply_duplicate_suppression(plan);
        m_suppression.reset();

        if(plan.empty())
            return;

        send_plan(plan);
    }

    // RFC 6762 section 7.4: a record type another responder multicast with a TTL at least ours is dropped.
    void apply_duplicate_suppression(answer_plan &plan)
    {
        if(m_suppression.empty())
            return;

        auto candidate_pkt = build_dns_response(m_ctx.info, dns_type::any, m_ctx.opts);
        std::vector<mdns_record_variant> candidates;
        walk_dns_frame(std::span<const std::byte>(candidate_pkt.data(), candidate_pkt.size()), endpoint{},
                       [&](mdns_record_variant rv) { candidates.push_back(std::move(rv)); });

        suppression_mask mask;
        for(const auto &rec : candidates)
        {
            uint32_t our_ttl = std::visit([](const auto &r) { return r.ttl; }, rec);
            if(m_suppression.is_suppressed(rec, our_ttl))
                mark_suppressed_type(mask, rec);
        }
        apply_suppression(plan, mask);
    }
};

}

#endif

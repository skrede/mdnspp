#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_ANSWER_PLAN_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_ANSWER_PLAN_H

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_query_match.h"
#include "mdnspp/detail/server_known_answer.h"

#include "mdnspp/service_info.h"

#include <span>

namespace mdnspp::detail {

// Each question is answered with the records owned by that name and of that qtype (RFC 6762 section 6); a name
// that exists without the qtype gets an NSEC negative response (RFC 6762 section 6.1).
struct answer_plan
{
    bool ptr{false};
    bool srv{false};
    bool txt{false};
    bool a{false};
    bool aaaa{false};
    bool nsec_service_type{false};
    bool nsec_service_name{false};
    bool nsec_hostname{false};

    bool has_answers() const noexcept
    {
        return ptr || srv || txt || a || aaaa;
    }

    bool has_nsec() const noexcept
    {
        return nsec_service_type || nsec_service_name || nsec_hostname;
    }

    bool empty() const noexcept
    {
        return !has_answers() && !has_nsec();
    }

    // RFC 6762 section 6: only shared records (PTR) need the 20-120 ms random delay.
    bool has_shared() const noexcept { return ptr; }

    void merge(const answer_plan &other) noexcept
    {
        ptr  = ptr  || other.ptr;
        srv  = srv  || other.srv;
        txt  = txt  || other.txt;
        a    = a    || other.a;
        aaaa = aaaa || other.aaaa;
        nsec_service_type = nsec_service_type || other.nsec_service_type;
        nsec_service_name = nsec_service_name || other.nsec_service_name;
        nsec_hostname     = nsec_hostname     || other.nsec_hostname;
    }
};

inline void plan_service_type_question(answer_plan &plan, dns_type qtype)
{
    if(qtype == dns_type::ptr || qtype == dns_type::any)
        plan.ptr = true;
    else
        plan.nsec_service_type = true;
}

inline void plan_service_name_question(answer_plan &plan, dns_type qtype)
{
    if(qtype == dns_type::any)
    {
        plan.srv = true;
        plan.txt = true;
    }
    else if(qtype == dns_type::srv)
        plan.srv = true;
    else if(qtype == dns_type::txt)
        plan.txt = true;
    else
        plan.nsec_service_name = true;
}

inline void plan_hostname_question(answer_plan &plan, dns_type qtype, const service_info &info)
{
    if(qtype == dns_type::any)
    {
        plan.a = info.address_ipv4.has_value();
        plan.aaaa = info.address_ipv6.has_value();
    }
    else if(qtype == dns_type::a)
    {
        if(info.address_ipv4.has_value())
            plan.a = true;
        else
            plan.nsec_hostname = true;
    }
    else if(qtype == dns_type::aaaa)
    {
        if(info.address_ipv6.has_value())
            plan.aaaa = true;
        else
            plan.nsec_hostname = true;
    }
    else
        plan.nsec_hostname = true;
}

inline answer_plan plan_answers(std::span<const question_match> questions, const service_info &info)
{
    answer_plan plan;
    for(const auto &q : questions)
    {
        switch(q.target)
        {
        case owned_name::service_type:
            plan_service_type_question(plan, q.qtype);
            break;
        case owned_name::service_name:
            plan_service_name_question(plan, q.qtype);
            break;
        case owned_name::hostname:
            plan_hostname_question(plan, q.qtype, info);
            break;
        }
    }
    return plan;
}

// The TC path has no original questions, so it plans every record this server owns (RFC 6762 section 7.2).
inline answer_plan plan_all_answers(const service_info &info)
{
    answer_plan plan;
    plan.ptr = true;
    plan.srv = true;
    plan.txt = true;
    plan.a = info.address_ipv4.has_value();
    plan.aaaa = info.address_ipv6.has_value();
    return plan;
}

// Known answers suppress records (RFC 6762 section 7.1) but never NSEC assertions.
inline void apply_suppression(answer_plan &plan, const suppression_mask &mask) noexcept
{
    plan.ptr  = plan.ptr  && !mask.ptr;
    plan.srv  = plan.srv  && !mask.srv;
    plan.txt  = plan.txt  && !mask.txt;
    plan.a    = plan.a    && !mask.a;
    plan.aaaa = plan.aaaa && !mask.aaaa;
}

// Queries arriving while the multicast response delay is pending join one response (RFC 6762 section 6.4).
struct pending_response
{
    bool armed{false};
    answer_plan plan{};

    void merge(const answer_plan &new_plan)
    {
        armed = true;
        plan.merge(new_plan);
    }

    void reset()
    {
        armed = false;
        plan = {};
    }
};

}

#endif

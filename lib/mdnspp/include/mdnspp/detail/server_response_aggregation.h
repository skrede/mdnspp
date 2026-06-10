#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_RESPONSE_AGGREGATION_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_RESPONSE_AGGREGATION_H

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_response.h"

#include "mdnspp/detail/server_query_match.h"
#include "mdnspp/detail/server_known_answer.h"

#include <span>
#include <chrono>
#include <string>
#include <vector>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <string_view>

namespace mdnspp::detail {

// The set of records (and NSEC negative assertions) a response will carry,
// derived from the per-question name<->qtype pairing (RFC 6762 §6).
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

    [[nodiscard]] bool has_answers() const noexcept
    {
        return ptr || srv || txt || a || aaaa;
    }

    [[nodiscard]] bool has_nsec() const noexcept
    {
        return nsec_service_type || nsec_service_name || nsec_hostname;
    }

    [[nodiscard]] bool empty() const noexcept
    {
        return !has_answers() && !has_nsec();
    }

    // RFC 6762 §6: only responses containing shared records (PTR) require the
    // 20-120 ms random delay; unique probe-verified records may go immediately.
    [[nodiscard]] bool has_shared() const noexcept { return ptr; }

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

// Derives the answer plan from matched questions. Each question is answered
// with records owned by THAT name and of THAT qtype (RFC 6762 §6); where the
// name exists but the qtype does not, an NSEC negative response for that name
// is planned (RFC 6762 §6.1).
inline answer_plan plan_answers(std::span<const question_match> questions,
                                const service_info &info)
{
    answer_plan plan;

    for(const auto &q : questions)
    {
        switch(q.target)
        {
        case owned_name::service_type:
            if(q.qtype == dns_type::ptr || q.qtype == dns_type::any)
                plan.ptr = true;
            else
                plan.nsec_service_type = true;
            break;
        case owned_name::service_name:
            if(q.qtype == dns_type::any)
            {
                plan.srv = true;
                plan.txt = true;
            }
            else if(q.qtype == dns_type::srv)
                plan.srv = true;
            else if(q.qtype == dns_type::txt)
                plan.txt = true;
            else
                plan.nsec_service_name = true;
            break;
        case owned_name::hostname:
            if(q.qtype == dns_type::any)
            {
                plan.a = info.address_ipv4.has_value();
                plan.aaaa = info.address_ipv6.has_value();
            }
            else if(q.qtype == dns_type::a)
            {
                if(info.address_ipv4.has_value())
                    plan.a = true;
                else
                    plan.nsec_hostname = true;
            }
            else if(q.qtype == dns_type::aaaa)
            {
                if(info.address_ipv6.has_value())
                    plan.aaaa = true;
                else
                    plan.nsec_hostname = true;
            }
            else
                plan.nsec_hostname = true;
            break;
        }
    }

    return plan;
}

// The full record set this server can answer with (used on the TC path where
// the original questions are not available; RFC 6762 §7.2).
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

// Removes record types suppressed by known answers (RFC 6762 §7.1). NSEC
// assertions are never suppressed.
inline void apply_suppression(answer_plan &plan, const suppression_mask &mask) noexcept
{
    plan.ptr  = plan.ptr  && !mask.ptr;
    plan.srv  = plan.srv  && !mask.srv;
    plan.txt  = plan.txt  && !mask.txt;
    plan.a    = plan.a    && !mask.a;
    plan.aaaa = plan.aaaa && !mask.aaaa;
}

// Aggregates queries arriving while the multicast response delay timer is
// pending into one combined response (RFC 6762 §6.4).
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

// Header and framing variations for the response packet.
struct response_header_options
{
    uint16_t id{0};                          // legacy unicast echoes the query ID (RFC 6762 §6.7)
    bool cache_flush{true};                  // legacy unicast must not set cache-flush
    bool include_nsec{true};
    uint32_t ttl_cap{UINT32_MAX};            // legacy unicast caps TTLs (RFC 6762 §6.7)
    std::span<const std::byte> questions{};  // legacy unicast repeats the question section
    uint16_t qdcount{0};
};

// Builds the response packet for an answer plan. Answers carry the planned
// record types; additionals follow RFC 6763 §12 (PTR pulls SRV/TXT/A/AAAA,
// SRV pulls A/AAAA) and NSEC negative assertions (RFC 6762 §6.1) with the
// owner being the name whose nonexistent type is asserted.
inline std::vector<std::byte> build_answer_response(const service_info &info,
                                                    const answer_plan &plan,
                                                    const service_options &opts,
                                                    const response_header_options &hdr = {})
{
    if(plan.empty())
        return {};

    auto w = encode_service_records(info);
    if(!w.valid)
        return {};

    auto ttl_for = [&](std::chrono::seconds t) -> uint32_t {
        return (std::min)(static_cast<uint32_t>(t.count()), hdr.ttl_cap);
    };

    auto is_unique = [&](dns_type t) -> bool {
        if(!hdr.cache_flush)
            return false;
        return t == dns_type::srv || t == dns_type::a ||
               t == dns_type::aaaa || t == dns_type::txt;
    };

    std::vector<std::byte> answers;
    std::vector<std::byte> additional;
    uint16_t ancount = 0;
    uint16_t arcount = 0;

    auto add_answer = [&](const std::vector<std::byte> &name, dns_type rtype,
                          uint32_t ttl, const std::vector<std::byte> &rdata)
    {
        append_dns_rr(answers, name, rtype, ttl, rdata, is_unique(rtype));
        ++ancount;
    };

    auto add_additional = [&](const std::vector<std::byte> &name, dns_type rtype,
                              uint32_t ttl, const std::vector<std::byte> &rdata)
    {
        append_dns_rr(additional, name, rtype, ttl, rdata, is_unique(rtype));
        ++arcount;
    };

    // Answer section: exactly the planned record types.
    if(plan.ptr)
        add_answer(w.name_service_type, dns_type::ptr, ttl_for(opts.ptr_ttl), w.rdata_ptr);
    if(plan.srv)
        add_answer(w.name_service_name, dns_type::srv, ttl_for(opts.srv_ttl), w.rdata_srv);
    if(plan.txt)
        add_answer(w.name_service_name, dns_type::txt, ttl_for(opts.txt_ttl), w.rdata_txt);
    if(plan.a && !w.rdata_a.empty())
        add_answer(w.name_hostname, dns_type::a, ttl_for(opts.a_ttl), w.rdata_a);
    if(plan.aaaa && !w.rdata_aaaa.empty())
        add_answer(w.name_hostname, dns_type::aaaa, ttl_for(opts.aaaa_ttl), w.rdata_aaaa);

    // Additional section per RFC 6763 §12: records the querier will need next.
    if(plan.ptr)
    {
        if(!plan.srv)
            add_additional(w.name_service_name, dns_type::srv, ttl_for(opts.srv_ttl), w.rdata_srv);
        if(!plan.txt)
            add_additional(w.name_service_name, dns_type::txt, ttl_for(opts.txt_ttl), w.rdata_txt);
    }
    if(plan.ptr || plan.srv)
    {
        if(!plan.a && !w.rdata_a.empty())
            add_additional(w.name_hostname, dns_type::a, ttl_for(opts.a_ttl), w.rdata_a);
        if(!plan.aaaa && !w.rdata_aaaa.empty())
            add_additional(w.name_hostname, dns_type::aaaa, ttl_for(opts.aaaa_ttl), w.rdata_aaaa);
    }

    // NSEC negative assertions (RFC 6762 §6.1): owner = the queried name whose
    // type does not exist; bitmap = the types that DO exist at that name.
    if(hdr.include_nsec)
    {
        uint32_t nsec_ttl = ttl_for(opts.record_ttl);
        auto add_nsec = [&](const std::vector<std::byte> &owner_name, nsec_owner owner)
        {
            std::size_t before = additional.size();
            append_nsec_rr(additional, owner_name, owner, info, nsec_ttl);
            if(additional.size() > before)
                ++arcount;
        };
        if(plan.nsec_service_type)
            add_nsec(w.name_service_type, nsec_owner::service_type);
        if(plan.nsec_service_name)
            add_nsec(w.name_service_name, nsec_owner::service_name);
        if(plan.nsec_hostname)
            add_nsec(w.name_hostname, nsec_owner::hostname);
    }

    if(ancount == 0 && arcount == 0)
        return {};

    std::vector<std::byte> packet;
    packet.reserve(12 + hdr.questions.size() + answers.size() + additional.size());

    push_u16_be(packet, hdr.id);
    push_u16_be(packet, 0x8400); // flags: QR=1, AA=1
    push_u16_be(packet, hdr.qdcount);
    push_u16_be(packet, ancount);
    push_u16_be(packet, 0x0000); // nscount
    push_u16_be(packet, arcount);

    packet.insert(packet.end(), hdr.questions.begin(), hdr.questions.end());
    packet.insert(packet.end(), answers.begin(), answers.end());
    packet.insert(packet.end(), additional.begin(), additional.end());

    return packet;
}

// Smallest TTL among the record types a plan would send; used for the QU
// quarter-TTL rule (RFC 6762 §5.4).
inline std::chrono::seconds min_planned_ttl(const answer_plan &plan, const service_options &opts)
{
    auto min_ttl = (std::chrono::seconds::max)();
    if(plan.ptr)  min_ttl = (std::min)(min_ttl, opts.ptr_ttl);
    if(plan.srv)  min_ttl = (std::min)(min_ttl, opts.srv_ttl);
    if(plan.txt)  min_ttl = (std::min)(min_ttl, opts.txt_ttl);
    if(plan.a)    min_ttl = (std::min)(min_ttl, opts.a_ttl);
    if(plan.aaaa) min_ttl = (std::min)(min_ttl, opts.aaaa_ttl);
    if(min_ttl == (std::chrono::seconds::max)())
        min_ttl = opts.record_ttl;
    return min_ttl;
}

// RFC 6762 §5.4: a QU question should nonetheless be answered via multicast
// when the record has not been multicast recently — within the last quarter
// of its TTL — so passive listeners and new joiners see the record.
template <typename TimePoint>
inline bool qu_requires_multicast(TimePoint last_multicast, TimePoint now,
                                  std::chrono::seconds min_ttl)
{
    return (now - last_multicast) > min_ttl / 4;
}

inline std::vector<std::byte> build_meta_query_response(const service_info &info,
                                                        uint32_t ttl = 4500)
{
    std::vector<std::byte> packet;
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x8400);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0001);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);

    auto owner = encode_dns_name(meta_query_name);
    auto rdata = encode_dns_name(info.service_type);
    append_dns_rr(packet, owner, dns_type::ptr, ttl, rdata, false);

    return packet;
}

inline std::vector<std::byte> build_subtype_response(std::string_view subtype_label,
                                                     const service_info &info,
                                                     uint32_t ttl = 4500)
{
    std::vector<std::byte> packet;
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x8400);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0001);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);

    auto subtype_name = std::string(subtype_label) + "._sub." + info.service_type.str();
    auto owner = encode_dns_name(subtype_name);
    auto rdata = encode_dns_name(info.service_name);
    append_dns_rr(packet, owner, dns_type::ptr, ttl, rdata, false);

    return packet;
}

}

#endif

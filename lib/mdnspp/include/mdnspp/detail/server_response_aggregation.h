#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_RESPONSE_AGGREGATION_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_RESPONSE_AGGREGATION_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/server_answer_plan.h"
#include "mdnspp/detail/dns_service_records.h"
#include "mdnspp/detail/server_meta_response.h"

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace mdnspp::detail {

struct response_header_options
{
    uint16_t id{0};                          // legacy unicast echoes the query ID (RFC 6762 §6.7)
    bool cache_flush{true};                  // legacy unicast must not set cache-flush
    bool include_nsec{true};
    uint32_t ttl_cap{UINT32_MAX};            // legacy unicast caps TTLs (RFC 6762 §6.7)
    std::span<const std::byte> questions{};  // legacy unicast repeats the question section
    uint16_t qdcount{0};
};

class answer_sections
{
public:
    explicit answer_sections(const response_header_options &hdr)
        : m_ancount(0)
        , m_arcount(0)
        , m_hdr(hdr)
    {
    }

    uint32_t ttl_for(std::chrono::seconds t) const
    {
        return (std::min)(static_cast<uint32_t>(t.count()), m_hdr.ttl_cap);
    }

    void add_answer(const std::vector<std::byte> &name, dns_type rtype, uint32_t ttl,
                    const std::vector<std::byte> &rdata)
    {
        append_dns_rr(m_answers, name, rtype, ttl, rdata, is_unique(rtype));
        ++m_ancount;
    }

    void add_additional(const std::vector<std::byte> &name, dns_type rtype, uint32_t ttl,
                        const std::vector<std::byte> &rdata)
    {
        append_dns_rr(m_additional, name, rtype, ttl, rdata, is_unique(rtype));
        ++m_arcount;
    }

    void add_nsec(const std::vector<std::byte> &owner_name, nsec_owner owner, const service_info &info, uint32_t ttl)
    {
        std::size_t before = m_additional.size();
        append_nsec_rr(m_additional, owner_name, owner, info, ttl);
        if(m_additional.size() > before)
            ++m_arcount;
    }

    std::vector<std::byte> assemble() const
    {
        if(m_ancount == 0 && m_arcount == 0)
            return {};
        std::vector<std::byte> packet;
        packet.reserve(12 + m_hdr.questions.size() + m_answers.size() + m_additional.size());
        push_u16_be(packet, m_hdr.id);
        push_u16_be(packet, 0x8400); // flags: QR=1, AA=1
        push_u16_be(packet, m_hdr.qdcount);
        push_u16_be(packet, m_ancount);
        push_u16_be(packet, 0x0000); // nscount
        push_u16_be(packet, m_arcount);
        packet.insert(packet.end(), m_hdr.questions.begin(), m_hdr.questions.end());
        packet.insert(packet.end(), m_answers.begin(), m_answers.end());
        packet.insert(packet.end(), m_additional.begin(), m_additional.end());
        return packet;
    }

private:
    uint16_t m_ancount;
    uint16_t m_arcount;
    std::vector<std::byte> m_answers;
    std::vector<std::byte> m_additional;
    const response_header_options &m_hdr;

    bool is_unique(dns_type t) const
    {
        if(!m_hdr.cache_flush)
            return false;
        return t == dns_type::srv || t == dns_type::a || t == dns_type::aaaa || t == dns_type::txt;
    }
};

inline void add_planned_answers(answer_sections &out, const answer_plan &plan, const service_wire_records &w,
                                const service_options &opts)
{
    if(plan.ptr)
        out.add_answer(w.name_service_type, dns_type::ptr, out.ttl_for(opts.ptr_ttl), w.rdata_ptr);
    if(plan.srv)
        out.add_answer(w.name_service_name, dns_type::srv, out.ttl_for(opts.srv_ttl), w.rdata_srv);
    if(plan.txt)
        out.add_answer(w.name_service_name, dns_type::txt, out.ttl_for(opts.txt_ttl), w.rdata_txt);
    if(plan.a && !w.rdata_a.empty())
        out.add_answer(w.name_hostname, dns_type::a, out.ttl_for(opts.a_ttl), w.rdata_a);
    if(plan.aaaa && !w.rdata_aaaa.empty())
        out.add_answer(w.name_hostname, dns_type::aaaa, out.ttl_for(opts.aaaa_ttl), w.rdata_aaaa);
}

// RFC 6763 section 12: a PTR answer pulls SRV, TXT and the addresses; an SRV answer pulls the addresses.
inline void add_planned_additionals(answer_sections &out, const answer_plan &plan, const service_wire_records &w,
                                    const service_options &opts)
{
    if(plan.ptr)
    {
        if(!plan.srv)
            out.add_additional(w.name_service_name, dns_type::srv, out.ttl_for(opts.srv_ttl), w.rdata_srv);
        if(!plan.txt)
            out.add_additional(w.name_service_name, dns_type::txt, out.ttl_for(opts.txt_ttl), w.rdata_txt);
    }
    if(plan.ptr || plan.srv)
    {
        if(!plan.a && !w.rdata_a.empty())
            out.add_additional(w.name_hostname, dns_type::a, out.ttl_for(opts.a_ttl), w.rdata_a);
        if(!plan.aaaa && !w.rdata_aaaa.empty())
            out.add_additional(w.name_hostname, dns_type::aaaa, out.ttl_for(opts.aaaa_ttl), w.rdata_aaaa);
    }
}

// RFC 6762 section 6.1: the NSEC owner is the queried name whose type does not exist; its bitmap lists the types
// that do.
inline void add_planned_nsec(answer_sections &out, const answer_plan &plan, const service_wire_records &w,
                             const service_info &info, const service_options &opts)
{
    uint32_t nsec_ttl = out.ttl_for(opts.fallback_record_ttl);
    if(plan.nsec_service_type)
        out.add_nsec(w.name_service_type, nsec_owner::service_type, info, nsec_ttl);
    if(plan.nsec_service_name)
        out.add_nsec(w.name_service_name, nsec_owner::service_name, info, nsec_ttl);
    if(plan.nsec_hostname)
        out.add_nsec(w.name_hostname, nsec_owner::hostname, info, nsec_ttl);
}

inline std::vector<std::byte> build_answer_response(const service_info &info, const answer_plan &plan,
                                                    const service_options &opts,
                                                    const response_header_options &hdr = {})
{
    if(plan.empty())
        return {};
    auto w = encode_service_records(info);
    if(!w.valid)
        return {};
    answer_sections out(hdr);
    add_planned_answers(out, plan, w, opts);
    add_planned_additionals(out, plan, w, opts);
    if(hdr.include_nsec)
        add_planned_nsec(out, plan, w, info, opts);
    return out.assemble();
}

// The QU quarter-TTL rule (RFC 6762 section 5.4) uses the smallest TTL a plan would send.
inline std::chrono::seconds min_planned_ttl(const answer_plan &plan, const service_options &opts)
{
    auto min_ttl = (std::chrono::seconds::max)();
    if(plan.ptr)  min_ttl = (std::min)(min_ttl, opts.ptr_ttl);
    if(plan.srv)  min_ttl = (std::min)(min_ttl, opts.srv_ttl);
    if(plan.txt)  min_ttl = (std::min)(min_ttl, opts.txt_ttl);
    if(plan.a)    min_ttl = (std::min)(min_ttl, opts.a_ttl);
    if(plan.aaaa) min_ttl = (std::min)(min_ttl, opts.aaaa_ttl);
    if(min_ttl == (std::chrono::seconds::max)())
        min_ttl = opts.fallback_record_ttl;
    return min_ttl;
}

// RFC 6762 section 5.4: a QU question is still answered by multicast when the record was not multicast within the
// last quarter of its TTL, so passive listeners and new joiners see it.
template <typename TimePoint>
inline bool qu_requires_multicast(TimePoint last_multicast, TimePoint now, std::chrono::seconds min_ttl)
{
    return (now - last_multicast) > min_ttl / 4;
}

}

#endif

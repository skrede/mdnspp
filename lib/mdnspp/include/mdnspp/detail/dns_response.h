#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_RESPONSE_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_RESPONSE_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_service_records.h"

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include <chrono>
#include <vector>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace mdnspp::detail {

struct response_ttls
{
    uint32_t ptr;
    uint32_t srv;
    uint32_t txt;
    uint32_t a;
    uint32_t aaaa;
};

// A cap below UINT32_MAX limits every TTL for legacy unicast responses (RFC 6762 section 6.7).
inline response_ttls make_response_ttls(const mdnspp::service_options &opts, uint32_t legacy_unicast_cap)
{
    auto ttl_for = [&](std::chrono::seconds t) -> uint32_t {
        return (std::min)(static_cast<uint32_t>(t.count()), legacy_unicast_cap);
    };
    return {ttl_for(opts.ptr_ttl), ttl_for(opts.srv_ttl), ttl_for(opts.txt_ttl), ttl_for(opts.a_ttl),
            ttl_for(opts.aaaa_ttl)};
}

class response_section
{
public:
    response_section()
        : m_count(0)
    {
    }

    // RFC 6762 section 10.2: PTR is shared and never cache-flush; SRV, A, AAAA and TXT are unique.
    void add(const std::vector<std::byte> &name, dns_type rtype, uint32_t ttl, const std::vector<std::byte> &rdata)
    {
        bool unique = rtype == dns_type::srv || rtype == dns_type::a || rtype == dns_type::aaaa ||
            rtype == dns_type::txt;
        append_dns_rr(m_bytes, name, rtype, ttl, rdata, unique);
        ++m_count;
    }

    void add_addresses(const service_wire_records &w, const response_ttls &ttls)
    {
        if(!w.rdata_a.empty())
            add(w.name_hostname, dns_type::a, ttls.a, w.rdata_a);
        if(!w.rdata_aaaa.empty())
            add(w.name_hostname, dns_type::aaaa, ttls.aaaa, w.rdata_aaaa);
    }

    uint16_t count() const { return m_count; }

    const std::vector<std::byte> &bytes() const { return m_bytes; }

private:
    uint16_t m_count;
    std::vector<std::byte> m_bytes;
};

inline void add_any_answers(response_section &answers, const service_wire_records &w, const response_ttls &ttls)
{
    answers.add(w.name_service_type, dns_type::ptr, ttls.ptr, w.rdata_ptr);
    answers.add(w.name_service_name, dns_type::srv, ttls.srv, w.rdata_srv);
    answers.add_addresses(w, ttls);
    answers.add(w.name_service_name, dns_type::txt, ttls.txt, w.rdata_txt);
}

inline bool add_answer_records(response_section &answers, dns_type qtype, const service_wire_records &w,
                               const response_ttls &ttls)
{
    switch(qtype)
    {
    case dns_type::ptr:
        answers.add(w.name_service_type, dns_type::ptr, ttls.ptr, w.rdata_ptr);
        return true;
    case dns_type::srv:
        answers.add(w.name_service_name, dns_type::srv, ttls.srv, w.rdata_srv);
        return true;
    case dns_type::a:
        answers.add(w.name_hostname, dns_type::a, ttls.a, w.rdata_a);
        return true;
    case dns_type::aaaa:
        answers.add(w.name_hostname, dns_type::aaaa, ttls.aaaa, w.rdata_aaaa);
        return true;
    case dns_type::txt:
        answers.add(w.name_service_name, dns_type::txt, ttls.txt, w.rdata_txt);
        return true;
    case dns_type::any:
        add_any_answers(answers, w, ttls);
        return true;
    default:
        return false;
    }
}

// The TXT record is mandatory for a DNS-SD instance (RFC 6763 section 6.1), so a PTR answer always carries it.
inline void add_additional_records(response_section &additional, dns_type qtype, const service_wire_records &w,
                                   const response_ttls &ttls)
{
    if(qtype == dns_type::ptr)
    {
        additional.add(w.name_service_name, dns_type::srv, ttls.srv, w.rdata_srv);
        additional.add_addresses(w, ttls);
        additional.add(w.name_service_name, dns_type::txt, ttls.txt, w.rdata_txt);
    }
    else if(qtype == dns_type::srv)
        additional.add_addresses(w, ttls);
}

inline std::vector<std::byte> assemble_response(const response_section &answers, const response_section &additional)
{
    std::vector<std::byte> packet;
    packet.reserve(12 + answers.bytes().size() + additional.bytes().size());
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x8400); // QR=1, AA=1
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, answers.count());
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, additional.count());
    packet.insert(packet.end(), answers.bytes().begin(), answers.bytes().end());
    packet.insert(packet.end(), additional.bytes().begin(), additional.bytes().end());
    return packet;
}

// RFC 6762 section 6 response layout with RFC 6763 DNS-SD additional records; empty for an unsupported query type
// or an address query whose address is unset.
inline std::vector<std::byte> build_dns_response(const mdnspp::service_info &info,
                                                 dns_type qtype,
                                                 const mdnspp::service_options &opts,
                                                 uint32_t legacy_unicast_cap = UINT32_MAX)
{
    auto ttls = make_response_ttls(opts, legacy_unicast_cap);
    auto w = encode_service_records(info);
    if(!w.valid)
        return {};
    if(qtype == dns_type::a && w.rdata_a.empty())
        return {};
    if(qtype == dns_type::aaaa && w.rdata_aaaa.empty())
        return {};
    response_section answers;
    response_section additional;
    if(!add_answer_records(answers, qtype, w, ttls))
        return {};
    add_additional_records(additional, qtype, w, ttls);
    return assemble_response(answers, additional);
}

}

#endif

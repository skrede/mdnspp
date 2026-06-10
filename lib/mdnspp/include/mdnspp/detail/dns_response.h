#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_RESPONSE_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_RESPONSE_H

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"

#include <vector>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <algorithm>

namespace mdnspp::detail {

// Pre-encoded wire forms of every record the service owns. Empty rdata_a /
// rdata_aaaa means the address is unset or failed to encode (the server
// validates and reports address errors separately via on_error).
// valid is false when a DNS name fails to encode.
struct service_wire_records
{
    std::vector<std::byte> name_service_type;
    std::vector<std::byte> name_service_name;
    std::vector<std::byte> name_hostname;
    std::vector<std::byte> rdata_ptr;
    std::vector<std::byte> rdata_srv;
    std::vector<std::byte> rdata_txt;
    std::vector<std::byte> rdata_a;
    std::vector<std::byte> rdata_aaaa;
    bool valid{false};
};

inline service_wire_records encode_service_records(const mdnspp::service_info &info)
{
    service_wire_records w;

    w.name_service_type = encode_dns_name(info.service_type);
    w.name_service_name = encode_dns_name(info.service_name);
    w.name_hostname = encode_dns_name(info.hostname);

    if(w.name_service_type.empty() || w.name_service_name.empty() || w.name_hostname.empty())
        return w;

    // PTR rdata: DNS-encoded service_name
    w.rdata_ptr = w.name_service_name;

    // SRV rdata: priority(2) + weight(2) + port(2) + DNS-encoded hostname
    push_u16_be(w.rdata_srv, info.priority);
    push_u16_be(w.rdata_srv, info.weight);
    push_u16_be(w.rdata_srv, info.port);
    w.rdata_srv.insert(w.rdata_srv.end(), w.name_hostname.begin(), w.name_hostname.end());

    // TXT rdata: length-prefixed key[=value] strings; a single zero byte when
    // there are no entries (RFC 6763 §6.1)
    w.rdata_txt = encode_txt_records(info.txt_records);

    if(info.address_ipv4.has_value())
    {
        if(auto enc = encode_ipv4(*info.address_ipv4); enc.has_value())
            w.rdata_a = std::move(*enc);
    }
    if(info.address_ipv6.has_value())
    {
        if(auto enc = encode_ipv6(*info.address_ipv6); enc.has_value())
            w.rdata_aaaa = std::move(*enc);
    }

    w.valid = true;
    return w;
}

// ---------------------------------------------------------------------------
// build_dns_response -- DNS response wire builder for mDNS service announcements
//
// Produces a complete mDNS response packet for the given service_info and query type.
// Follows RFC 6762 section 6 (response format) and RFC 6763 (DNS-SD record layout):
//
//   qtype=12  (PTR): answer=PTR, additional=SRV + A/AAAA (if available) + TXT
//   qtype=33  (SRV): answer=SRV, additional=A/AAAA (if available)
//   qtype=1   (A):   answer=A (owner=hostname); empty vector if no address_ipv4
//   qtype=28  (AAAA): answer=AAAA (owner=hostname); empty vector if no address_ipv6
//   qtype=16  (TXT): answer=TXT (owner=service_name)
//   qtype=255 (ANY): all available records as answers
//   other:           empty vector
//
// The TXT record is always present in PTR/ANY responses; with no TXT entries
// its rdata is a single zero byte (RFC 6763 §6.1).
//
// Header: id=0, flags=0x8400 (QR=1, AA=1), qdcount=0, ancount and arcount set from content.
//
// Per-type TTLs are taken from opts (ptr_ttl, srv_ttl, txt_ttl, a_ttl, aaaa_ttl).
//
// legacy_unicast_cap: when set to a value below UINT32_MAX, each record TTL is
// capped at min(per_type_ttl, legacy_unicast_cap) per RFC 6762 section 6.7.
// ---------------------------------------------------------------------------
inline std::vector<std::byte> build_dns_response(const mdnspp::service_info &info,
                                                 dns_type qtype,
                                                 const mdnspp::service_options &opts,
                                                 uint32_t legacy_unicast_cap = UINT32_MAX)
{
    // Derive per-type TTL values, capped for legacy unicast if requested.
    auto ttl_for = [&](std::chrono::seconds t) -> uint32_t {
        return (std::min)(static_cast<uint32_t>(t.count()), legacy_unicast_cap);
    };
    uint32_t ptr_t  = ttl_for(opts.ptr_ttl);
    uint32_t srv_t  = ttl_for(opts.srv_ttl);
    uint32_t txt_t  = ttl_for(opts.txt_ttl);
    uint32_t a_t    = ttl_for(opts.a_ttl);
    uint32_t aaaa_t = ttl_for(opts.aaaa_ttl);

    auto w = encode_service_records(info);
    if(!w.valid)
        return {};

    // Handle unresolvable cases early
    if(qtype == dns_type::a && w.rdata_a.empty())
        return {};
    if(qtype == dns_type::aaaa && w.rdata_aaaa.empty())
        return {};

    // Allocate answer and additional RR buffers
    std::vector<std::byte> answers;
    std::vector<std::byte> additional;
    uint16_t ancount = 0;
    uint16_t arcount = 0;

    // Unique record types get cache-flush bit set (RFC 6762 section 10.2).
    // PTR is shared (never cache-flush); SRV, A, AAAA, TXT are unique (always cache-flush).
    auto is_unique = [](dns_type t) -> bool {
        return t == dns_type::srv || t == dns_type::a ||
               t == dns_type::aaaa || t == dns_type::txt;
    };

    // Helper lambdas to append to the right section
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

    // Helper: add A and AAAA records to a section
    auto append_address_records = [&](auto add_fn)
    {
        if(!w.rdata_a.empty())
            add_fn(w.name_hostname, dns_type::a, a_t, w.rdata_a);
        if(!w.rdata_aaaa.empty())
            add_fn(w.name_hostname, dns_type::aaaa, aaaa_t, w.rdata_aaaa);
    };

    switch(qtype)
    {
    case dns_type::ptr: // PTR -- service type lookup
        {
            // Answer: PTR record (owner = service_type)
            add_answer(w.name_service_type, dns_type::ptr, ptr_t, w.rdata_ptr);
            // Additional: SRV
            add_additional(w.name_service_name, dns_type::srv, srv_t, w.rdata_srv);
            // Additional: A / AAAA
            append_address_records(add_additional);
            // Additional: TXT (mandatory for DNS-SD instances, RFC 6763 §6.1)
            add_additional(w.name_service_name, dns_type::txt, txt_t, w.rdata_txt);
            break;
        }
    case dns_type::srv: // SRV -- service instance lookup
        {
            add_answer(w.name_service_name, dns_type::srv, srv_t, w.rdata_srv);
            append_address_records(add_additional);
            break;
        }
    case dns_type::a: // A -- hostname lookup (IPv4)
        {
            add_answer(w.name_hostname, dns_type::a, a_t, w.rdata_a);
            break;
        }
    case dns_type::aaaa: // AAAA -- hostname lookup (IPv6)
        {
            add_answer(w.name_hostname, dns_type::aaaa, aaaa_t, w.rdata_aaaa);
            break;
        }
    case dns_type::txt: // TXT -- service metadata
        {
            // With no entries the rdata is a single zero byte (RFC 6763 §6.1)
            add_answer(w.name_service_name, dns_type::txt, txt_t, w.rdata_txt);
            break;
        }
    case dns_type::any: // ANY -- all available records
        {
            add_answer(w.name_service_type, dns_type::ptr, ptr_t, w.rdata_ptr);
            add_answer(w.name_service_name, dns_type::srv, srv_t, w.rdata_srv);
            if(!w.rdata_a.empty())
                add_answer(w.name_hostname, dns_type::a, a_t, w.rdata_a);
            if(!w.rdata_aaaa.empty())
                add_answer(w.name_hostname, dns_type::aaaa, aaaa_t, w.rdata_aaaa);
            add_answer(w.name_service_name, dns_type::txt, txt_t, w.rdata_txt);
            break;
        }
    default:
        return {}; // Unknown query type -- no response
    }

    // Assemble the final packet: 12-byte header + answers + additional
    std::vector<std::byte> packet;
    packet.reserve(12 + answers.size() + additional.size());

    // DNS header
    push_u16_be(packet, 0x0000); // id = 0
    push_u16_be(packet, 0x8400); // flags: QR=1, AA=1 (mDNS authoritative response)
    push_u16_be(packet, 0x0000); // qdcount = 0
    push_u16_be(packet, ancount);
    push_u16_be(packet, 0x0000); // nscount = 0
    push_u16_be(packet, arcount);

    packet.insert(packet.end(), answers.begin(), answers.end());
    packet.insert(packet.end(), additional.begin(), additional.end());

    return packet;
}

}

#endif

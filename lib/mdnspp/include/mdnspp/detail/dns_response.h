#ifndef HPP_GUARD_MDNSPP_DNS_RESPONSE_H
#define HPP_GUARD_MDNSPP_DNS_RESPONSE_H

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"

#include <vector>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

// ---------------------------------------------------------------------------
// build_dns_response -- DNS response wire builder for mDNS service announcements
//
// Produces a complete mDNS response packet for the given service_info and query type.
// Follows RFC 6762 section 6 (response format) and RFC 6763 (DNS-SD record layout):
//
//   qtype=12  (PTR): answer=PTR, additional=SRV + A/AAAA (if available) + TXT (if any)
//   qtype=33  (SRV): answer=SRV, additional=A/AAAA (if available)
//   qtype=1   (A):   answer=A (owner=hostname); empty vector if no address_ipv4
//   qtype=28  (AAAA): answer=AAAA (owner=hostname); empty vector if no address_ipv6
//   qtype=16  (TXT): answer=TXT (owner=service_name)
//   qtype=255 (ANY): all available records as answers
//   other:           empty vector
//
// Header: id=0, flags=0x8400 (QR=1, AA=1), qdcount=0, ancount and arcount set from content.
// Default TTL: 4500 seconds (RFC 6762 recommended).
// ---------------------------------------------------------------------------
inline std::vector<std::byte> build_dns_response(const mdnspp::service_info &info,
                                                 dns_type qtype,
                                                 uint32_t default_ttl = 4500)
{
    // Pre-encode frequently used names
    auto name_service_type = encode_dns_name(info.service_type);
    auto name_service_name = encode_dns_name(info.service_name);
    auto name_hostname = encode_dns_name(info.hostname);

    // Build rdata buffers for each record type
    // PTR rdata: DNS-encoded service_name
    auto rdata_ptr = name_service_name;

    // SRV rdata: priority(2) + weight(2) + port(2) + DNS-encoded hostname
    std::vector<std::byte> rdata_srv;
    push_u16_be(rdata_srv, info.priority);
    push_u16_be(rdata_srv, info.weight);
    push_u16_be(rdata_srv, info.port);
    rdata_srv.insert(rdata_srv.end(), name_hostname.begin(), name_hostname.end());

    // A rdata: 4 IPv4 octets (may be empty if no address_ipv4)
    std::vector<std::byte> rdata_a;
    if(info.address_ipv4.has_value())
        rdata_a = encode_ipv4(*info.address_ipv4);

    // AAAA rdata: 16 IPv6 bytes (may be empty if no address_ipv6)
    std::vector<std::byte> rdata_aaaa;
    if(info.address_ipv6.has_value())
        rdata_aaaa = encode_ipv6(*info.address_ipv6);

    // TXT rdata: length-prefixed key[=value] strings
    std::vector<std::byte> rdata_txt;
    if(!info.txt_records.empty())
        rdata_txt = encode_txt_records(info.txt_records);

    // Handle unresolvable cases early
    if(qtype == dns_type::a && rdata_a.empty())
        return {};
    if(qtype == dns_type::aaaa && rdata_aaaa.empty())
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
        if(!rdata_a.empty())
            add_fn(name_hostname, dns_type::a, default_ttl, rdata_a);
        if(!rdata_aaaa.empty())
            add_fn(name_hostname, dns_type::aaaa, default_ttl, rdata_aaaa);
    };

    switch(qtype)
    {
    case dns_type::ptr: // PTR -- service type lookup
        {
            // Answer: PTR record (owner = service_type)
            add_answer(name_service_type, dns_type::ptr, default_ttl, rdata_ptr);
            // Additional: SRV
            add_additional(name_service_name, dns_type::srv, default_ttl, rdata_srv);
            // Additional: A / AAAA
            append_address_records(add_additional);
            // Additional: TXT (if any)
            if(!rdata_txt.empty())
                add_additional(name_service_name, dns_type::txt, default_ttl, rdata_txt);
            break;
        }
    case dns_type::srv: // SRV -- service instance lookup
        {
            add_answer(name_service_name, dns_type::srv, default_ttl, rdata_srv);
            append_address_records(add_additional);
            break;
        }
    case dns_type::a: // A -- hostname lookup (IPv4)
        {
            add_answer(name_hostname, dns_type::a, default_ttl, rdata_a);
            break;
        }
    case dns_type::aaaa: // AAAA -- hostname lookup (IPv6)
        {
            add_answer(name_hostname, dns_type::aaaa, default_ttl, rdata_aaaa);
            break;
        }
    case dns_type::txt: // TXT -- service metadata
        {
            // Even if txt_records is empty, produce a valid (zero-length) TXT record
            add_answer(name_service_name, dns_type::txt, default_ttl, rdata_txt);
            break;
        }
    case dns_type::any: // ANY -- all available records
        {
            add_answer(name_service_type, dns_type::ptr, default_ttl, rdata_ptr);
            add_answer(name_service_name, dns_type::srv, default_ttl, rdata_srv);
            if(!rdata_a.empty())
                add_answer(name_hostname, dns_type::a, default_ttl, rdata_a);
            if(!rdata_aaaa.empty())
                add_answer(name_hostname, dns_type::aaaa, default_ttl, rdata_aaaa);
            if(!rdata_txt.empty())
                add_answer(name_service_name, dns_type::txt, default_ttl, rdata_txt);
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

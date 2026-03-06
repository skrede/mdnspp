#ifndef HPP_GUARD_MDNSPP_DNS_WIRE_H
#define HPP_GUARD_MDNSPP_DNS_WIRE_H

#include "mdnspp/parse.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/platform.h"

#include <span>
#include <sstream>
#include <utility>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace mdnspp::detail {

// Builds a complete mDNS query packet:
//   12-byte header (id=0, flags=0, questions=1, answers=0, authority=0, additional=0)
//   + DNS-encoded name
//   + qtype (big-endian, 2 bytes)
//   + qclass (2 bytes): 0x0001 (IN) or 0x8001 (IN + QU bit, RFC 6762 §5.4)
inline std::vector<std::byte> build_dns_query(std::string_view name, dns_type qtype,
                                              bool unicast = false)
{
    std::vector<std::byte> packet;
    packet.reserve(12 + 256 + 4);

    // 12-byte DNS header
    // Transaction ID: 0x0000
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));
    // Flags: 0x0000 (standard query)
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));
    // Questions: 1
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x01));
    // Answers: 0
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));
    // Authority: 0
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));
    // Additional: 0
    packet.push_back(static_cast<std::byte>(0x00));
    packet.push_back(static_cast<std::byte>(0x00));

    // Encoded question name
    auto encoded = encode_dns_name(name);
    packet.insert(packet.end(), encoded.begin(), encoded.end());

    // QTYPE (big-endian)
    push_u16_be(packet, std::to_underlying(qtype));

    // QCLASS: IN (0x0001) with optional QU bit (bit 15) per RFC 6762 §5.4
    push_u16_be(packet, unicast ? uint16_t{0x8001} : uint16_t{0x0001});

    return packet;
}

// Walks a DNS response frame, calling on_record(mdns_record_variant) for each
// successfully parsed resource record. Silently skips malformed records.
//
// Template parameter Callback: callable accepting mdns_record_variant by value.
template <typename Callback>
void walk_dns_frame(std::span<const std::byte> data, endpoint sender, Callback &&on_record)
{
    // Need at least 12 bytes for DNS header
    if(data.size() < 12)
        return;

    const std::byte *buf = data.data();

    // Parse header counts
    uint16_t qdcount = read_u16_be(buf + 4);  // questions
    uint16_t ancount = read_u16_be(buf + 6);  // answers
    uint16_t nscount = read_u16_be(buf + 8);  // authority
    uint16_t arcount = read_u16_be(buf + 10); // additional

    size_t offset = 12;

    // Skip questions section (name + qtype(2) + qclass(2))
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        if(!skip_dns_name(data, offset))
            return;
        offset += 4; // qtype + qclass
        if(offset > data.size())
            return;
    }

    // Parse RRs: answer + authority + additional
    uint32_t rr_total = static_cast<uint32_t>(ancount) +
        static_cast<uint32_t>(nscount) +
        static_cast<uint32_t>(arcount);

    for(uint32_t rr = 0; rr < rr_total; ++rr)
    {
        // Record name offset (for record_metadata.name_offset)
        size_t name_offset = offset;

        if(!skip_dns_name(data, offset))
            return;

        // Need rtype(2) + rclass(2) + ttl(4) + rdlength(2) = 10 bytes
        if(offset + 10 > data.size())
            return;

        dns_type rtype = static_cast<dns_type>(read_u16_be(buf + offset));
        offset += 2;
        uint16_t rclass = read_u16_be(buf + offset);
        offset += 2;
        uint32_t ttl = read_u32_be(buf + offset);
        offset += 4;
        uint16_t rdlength = read_u16_be(buf + offset);
        offset += 2;

        size_t record_offset = offset;
        size_t record_length = static_cast<size_t>(rdlength);

        // Bounds check for rdata
        if(record_offset + record_length > data.size())
            return;

        record_metadata meta;
        meta.sender = sender;
        meta.ttl = ttl;
        meta.rclass = static_cast<dns_class>(rclass & 0x7FFF); // strip cache-flush bit
        meta.rtype = rtype;
        meta.name_offset = name_offset;
        meta.record_offset = record_offset;
        meta.record_length = record_length;

        // Attempt to parse the record; silently skip on failure
        auto result = parse::record(data, meta);
        if(result.has_value())
            on_record(std::move(*result));

        // Advance past rdata regardless of parse success
        offset = record_offset + record_length;
    }
}

// ---------------------------------------------------------------------------
// build_dns_response helpers (private to this translation unit)
// ---------------------------------------------------------------------------

namespace response_detail {

// Appends a complete DNS resource record to buf.
//   name  — owner name (DNS wire format, pre-encoded)
//   rtype — DNS record type
//   ttl   — 32-bit TTL in seconds
//   rdata — the raw rdata bytes
inline void append_dns_rr(std::vector<std::byte> &buf,
                          const std::vector<std::byte> &name,
                          dns_type rtype,
                          uint32_t ttl,
                          const std::vector<std::byte> &rdata)
{
    buf.insert(buf.end(), name.begin(), name.end());
    push_u16_be(buf, std::to_underlying(rtype));
    push_u16_be(buf, 0x0001); // class IN
    push_u32_be(buf, ttl);
    push_u16_be(buf, static_cast<uint16_t>(rdata.size()));
    buf.insert(buf.end(), rdata.begin(), rdata.end());
}

// Encodes an IPv4 address string "a.b.c.d" into 4 raw bytes.
// Returns empty vector on parse failure.
inline std::vector<std::byte> encode_ipv4(const std::string &addr)
{
    std::vector<std::byte> result;
    std::istringstream ss(addr);
    std::string token;
    while(std::getline(ss, token, '.'))
    {
        int octet = std::stoi(token);
        if(octet < 0 || octet > 255)
            return {};
        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(octet)));
    }
    if(result.size() != 4)
        return {};
    return result;
}

// Encodes an IPv6 address string into 16 raw bytes using inet_pton.
// Returns empty vector on parse failure.
inline std::vector<std::byte> encode_ipv6(const std::string &addr)
{
    uint8_t raw[16];
    if(::inet_pton(AF_INET6, addr.c_str(), raw) != 1)
        return {};
    std::vector<std::byte> result;
    result.reserve(16);
    for(auto b : raw)
        result.push_back(static_cast<std::byte>(b));
    return result;
}

// Encodes a vector of service_txt entries as RFC 6763 TXT rdata.
// Each entry becomes a length-prefixed string of "key=value" or "key".
inline std::vector<std::byte> encode_txt_records(const std::vector<mdnspp::service_txt> &entries)
{
    std::vector<std::byte> result;
    for(const auto &entry : entries)
    {
        std::string s = entry.key;
        if(entry.value.has_value())
        {
            s += '=';
            s += *entry.value;
        }
        // Length prefix (clamped to 255 per RFC 6763)
        uint8_t len = static_cast<uint8_t>(s.size() < 255 ? s.size() : 255);
        result.push_back(static_cast<std::byte>(len));
        for(size_t i = 0; i < len; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(s[i])));
    }
    return result;
}

} // namespace response_detail

// ---------------------------------------------------------------------------
// build_dns_response — DNS response wire builder for mDNS service announcements
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
    using namespace response_detail;

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

    // Helper lambdas to append to the right section
    auto add_answer = [&](const std::vector<std::byte> &name, dns_type rtype,
                          uint32_t ttl, const std::vector<std::byte> &rdata)
    {
        append_dns_rr(answers, name, rtype, ttl, rdata);
        ++ancount;
    };

    auto add_additional = [&](const std::vector<std::byte> &name, dns_type rtype,
                              uint32_t ttl, const std::vector<std::byte> &rdata)
    {
        append_dns_rr(additional, name, rtype, ttl, rdata);
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
    case dns_type::ptr: // PTR — service type lookup
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
    case dns_type::srv: // SRV — service instance lookup
        {
            add_answer(name_service_name, dns_type::srv, default_ttl, rdata_srv);
            append_address_records(add_additional);
            break;
        }
    case dns_type::a: // A — hostname lookup (IPv4)
        {
            add_answer(name_hostname, dns_type::a, default_ttl, rdata_a);
            break;
        }
    case dns_type::aaaa: // AAAA — hostname lookup (IPv6)
        {
            add_answer(name_hostname, dns_type::aaaa, default_ttl, rdata_aaaa);
            break;
        }
    case dns_type::txt: // TXT — service metadata
        {
            // Even if txt_records is empty, produce a valid (zero-length) TXT record
            add_answer(name_service_name, dns_type::txt, default_ttl, rdata_txt);
            break;
        }
    case dns_type::any: // ANY — all available records
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
        return {}; // Unknown query type — no response
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

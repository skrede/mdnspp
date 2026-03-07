#ifndef HPP_GUARD_MDNSPP_DNS_WIRE_H
#define HPP_GUARD_MDNSPP_DNS_WIRE_H

#include "mdnspp/parse.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/platform.h"

#include <span>
#include <string>
#include <vector>
#include <variant>
#include <cstddef>
#include <cstdint>
#include <sstream>
#include <utility>
#include <string_view>

namespace mdnspp::detail {

// Builds a complete mDNS query packet:
//   12-byte header (id=0, flags=0, questions=1, answers=0, authority=0, additional=0)
//   + DNS-encoded name
//   + qtype (big-endian, 2 bytes)
//   + qclass (2 bytes): 0x0001 (IN) or 0x8001 (IN + QU bit, RFC 6762 §5.4)
inline std::vector<std::byte> build_dns_query(std::string_view name, dns_type qtype,
                                              response_mode mode = response_mode::multicast)
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
    push_u16_be(packet, mode == response_mode::unicast ? uint16_t{0x8001} : uint16_t{0x0001});

    return packet;
}

// Walks a DNS response frame, calling on_record(mdns_record_variant) for each
// successfully parsed resource record. Silently skips malformed records.
//
// Template parameter Callback: callable accepting mdns_record_variant by value.
template <typename Callback>
void walk_dns_frame(std::span<const std::byte> data, const endpoint &sender, Callback &&on_record)
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
                          const std::vector<std::byte> &rdata,
                          bool cache_flush = false)
{
    buf.insert(buf.end(), name.begin(), name.end());
    push_u16_be(buf, std::to_underlying(rtype));
    push_u16_be(buf, cache_flush ? uint16_t{0x8001} : uint16_t{0x0001});
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

// Builds an RFC 4034 section 4.1.2 window-block-0 type bitmap for NSEC records.
// Sets bits for PTR(12), TXT(16), SRV(33), and conditionally A(1) and AAAA(28)
// based on the service_info address fields. NSEC(47) is NOT set per RFC 6762 section 6.1.
// Returns the complete window block: [window=0x00][bitmap_length][bitmap bytes...].
// Trailing zero bytes are trimmed per RFC 4034 section 4.1.2.
inline std::vector<std::byte> build_nsec_bitmap(const mdnspp::service_info &info)
{
    // Highest type bit we need is SRV=33, which falls in byte index 4 (covers types 32-39).
    // Allocate 5 bytes (types 0-39).
    std::vector<uint8_t> bitmap(5, 0);

    auto set_bit = [&](uint16_t type_val)
    {
        bitmap[type_val / 8] |= static_cast<uint8_t>(1u << (7u - (type_val % 8u)));
    };

    // Always set PTR(12), TXT(16), SRV(33)
    set_bit(std::to_underlying(dns_type::ptr));  // 12
    set_bit(std::to_underlying(dns_type::txt));  // 16
    set_bit(std::to_underlying(dns_type::srv));  // 33

    // Conditionally set A(1) and AAAA(28)
    if(info.address_ipv4.has_value())
        set_bit(std::to_underlying(dns_type::a));    // 1
    if(info.address_ipv6.has_value())
        set_bit(std::to_underlying(dns_type::aaaa)); // 28

    // Trim trailing zero bytes
    while(!bitmap.empty() && bitmap.back() == 0)
        bitmap.pop_back();

    // Build window block: [window=0x00][length][bitmap bytes...]
    std::vector<std::byte> result;
    result.reserve(2 + bitmap.size());
    result.push_back(std::byte{0x00}); // window number
    result.push_back(static_cast<std::byte>(bitmap.size()));
    for(auto b : bitmap)
        result.push_back(static_cast<std::byte>(b));

    return result;
}

// Appends a complete NSEC resource record to buf.
// NSEC rdata = next domain name (same as owner for mDNS, per RFC 6762 section 6.1)
//            + type bitmap from build_nsec_bitmap.
// No cache-flush bit for NSEC records.
inline void append_nsec_rr(std::vector<std::byte> &buf,
                           const std::vector<std::byte> &owner_name,
                           const mdnspp::service_info &info,
                           uint32_t ttl)
{
    auto bitmap = build_nsec_bitmap(info);
    std::vector<std::byte> rdata;
    rdata.reserve(owner_name.size() + bitmap.size());
    rdata.insert(rdata.end(), owner_name.begin(), owner_name.end());
    rdata.insert(rdata.end(), bitmap.begin(), bitmap.end());
    append_dns_rr(buf, owner_name, dns_type::nsec, ttl, rdata);
}

}

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

// Builds an mDNS probe query per RFC 6762 section 8.1:
//   - Header: id=0, flags=0x0000 (query), qdcount=1, ancount=0, nscount=1, arcount=0
//   - Question: service_name, QTYPE=ANY (0x00FF), QCLASS=IN|QU (0x8001)
//   - Authority: proposed SRV record for simultaneous probe tiebreaking (RFC 6762 section 8.2)
inline std::vector<std::byte> build_probe_query(const service_info &info)
{
    auto name_service = encode_dns_name(info.service_name);
    auto name_host = encode_dns_name(info.hostname);

    // Build SRV rdata: priority(2) + weight(2) + port(2) + encoded hostname
    std::vector<std::byte> rdata_srv;
    push_u16_be(rdata_srv, info.priority);
    push_u16_be(rdata_srv, info.weight);
    push_u16_be(rdata_srv, info.port);
    rdata_srv.insert(rdata_srv.end(), name_host.begin(), name_host.end());

    std::vector<std::byte> packet;
    packet.reserve(12 + name_service.size() + 4 + name_service.size() + 10 + rdata_srv.size());

    // DNS header
    push_u16_be(packet, 0x0000); // id = 0
    push_u16_be(packet, 0x0000); // flags = 0x0000 (standard query)
    push_u16_be(packet, 0x0001); // qdcount = 1
    push_u16_be(packet, 0x0000); // ancount = 0
    push_u16_be(packet, 0x0001); // nscount = 1
    push_u16_be(packet, 0x0000); // arcount = 0

    // Question section: service_name, QTYPE=ANY, QCLASS=IN|QU
    packet.insert(packet.end(), name_service.begin(), name_service.end());
    push_u16_be(packet, std::to_underlying(dns_type::any)); // QTYPE = ANY (0x00FF)
    push_u16_be(packet, uint16_t{0x8001}); // QCLASS = IN | QU bit

    // Authority section: proposed SRV record
    response_detail::append_dns_rr(packet, name_service, dns_type::srv, 120, rdata_srv);

    return packet;
}

// Serializes an mdns_record_variant as a DNS resource record into buf.
// Used for known-answer suppression (RFC 6762 section 7.1): records are
// appended to the Answer section of a query packet. No cache-flush bit.
inline void append_known_answer(std::vector<std::byte> &buf, const mdns_record_variant &rec)
{
    std::visit([&buf](const auto &r)
    {
        auto name = encode_dns_name(r.name);

        using T = std::decay_t<decltype(r)>;

        if constexpr(std::is_same_v<T, record_ptr>)
        {
            auto rdata = encode_dns_name(r.ptr_name);
            response_detail::append_dns_rr(buf, name, dns_type::ptr, r.ttl, rdata);
        }
        else if constexpr(std::is_same_v<T, record_srv>)
        {
            std::vector<std::byte> rdata;
            push_u16_be(rdata, r.priority);
            push_u16_be(rdata, r.weight);
            push_u16_be(rdata, r.port);
            auto target = encode_dns_name(r.srv_name);
            rdata.insert(rdata.end(), target.begin(), target.end());
            response_detail::append_dns_rr(buf, name, dns_type::srv, r.ttl, rdata);
        }
        else if constexpr(std::is_same_v<T, record_a>)
        {
            auto rdata = response_detail::encode_ipv4(r.address_string);
            if(!rdata.empty())
                response_detail::append_dns_rr(buf, name, dns_type::a, r.ttl, rdata);
        }
        else if constexpr(std::is_same_v<T, record_aaaa>)
        {
            auto rdata = response_detail::encode_ipv6(r.address_string);
            if(!rdata.empty())
                response_detail::append_dns_rr(buf, name, dns_type::aaaa, r.ttl, rdata);
        }
        else if constexpr(std::is_same_v<T, record_txt>)
        {
            auto rdata = response_detail::encode_txt_records(r.entries);
            response_detail::append_dns_rr(buf, name, dns_type::txt, r.ttl, rdata);
        }
    }, rec);
}

// Builds a DNS query with known-answer records appended in the Answer section
// (RFC 6762 section 7.1). The header ancount is updated to reflect the number
// of known answers actually serialized.
inline std::vector<std::byte> build_dns_query(std::string_view name, dns_type qtype,
                                              std::span<const mdns_record_variant> known_answers,
                                              response_mode mode = response_mode::multicast)
{
    auto packet = build_dns_query(name, qtype, mode);

    uint16_t ancount = 0;
    for(const auto &ka : known_answers)
    {
        size_t before = packet.size();
        append_known_answer(packet, ka);
        if(packet.size() > before)
            ++ancount;
    }

    // Update header ancount (bytes 6-7)
    packet[6] = static_cast<std::byte>(static_cast<uint8_t>(ancount >> 8));
    packet[7] = static_cast<std::byte>(static_cast<uint8_t>(ancount & 0xFF));

    return packet;
}

}

namespace mdnspp {

// Service type information parsed from a DNS-SD PTR name.
struct service_type_info
{
    std::string service_type; // full: "_http._tcp.local" or "_http._tcp.local."
    std::string type_name;    // "_http"
    std::string protocol;     // "_tcp"
    std::string domain;       // "local"
};

// Parses a DNS-SD service type name (e.g. "_http._tcp.local") into components.
// Expects at least three dot-separated labels: type, protocol, domain.
inline service_type_info parse_service_type(std::string_view name)
{
    // Strip trailing dot if present
    if(!name.empty() && name.back() == '.')
        name.remove_suffix(1);

    service_type_info info;
    info.service_type = std::string(name);

    // Split on dots
    size_t first_dot = name.find('.');
    if(first_dot == std::string_view::npos)
        return info;

    info.type_name = std::string(name.substr(0, first_dot));

    size_t second_dot = name.find('.', first_dot + 1);
    if(second_dot == std::string_view::npos)
    {
        info.protocol = std::string(name.substr(first_dot + 1));
        return info;
    }

    info.protocol = std::string(name.substr(first_dot + 1, second_dot - first_dot - 1));
    info.domain = std::string(name.substr(second_dot + 1));

    return info;
}

}

#endif

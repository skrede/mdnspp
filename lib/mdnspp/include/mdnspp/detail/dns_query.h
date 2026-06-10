#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_QUERY_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_QUERY_H

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <string>
#include <vector>
#include <utility>
#include <cstddef>
#include <cstdint>
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

    // Encoded question name (empty = encoding failure)
    auto encoded = encode_dns_name(name);
    if(encoded.empty())
        return {};
    packet.insert(packet.end(), encoded.begin(), encoded.end());

    // QTYPE (big-endian)
    push_u16_be(packet, detail::to_underlying(qtype));

    // QCLASS: IN (0x0001) with optional QU bit (bit 15) per RFC 6762 §5.4
    push_u16_be(packet, mode == response_mode::unicast ? uint16_t{0x8001} : uint16_t{0x0001});

    return packet;
}

// One record of the proposed unique record set carried in probe queries and
// used for RFC 6762 section 8.2.1 tiebreaking.
struct proposed_record
{
    std::vector<std::byte> owner;
    dns_type rtype{dns_type::none};
    std::vector<std::byte> rdata;
};

// Builds the full proposed unique record set (SRV + TXT + A/AAAA) for the
// service. Returns an empty vector when a name fails to encode; address
// encoding failures merely omit the corresponding address record (the caller
// validates and reports addresses separately).
inline std::vector<proposed_record> build_proposed_records(const service_info &info)
{
    auto name_service = encode_dns_name(info.service_name);
    auto name_host = encode_dns_name(info.hostname);

    if(name_service.empty() || name_host.empty())
        return {};

    std::vector<proposed_record> records;
    records.reserve(4);

    // SRV rdata: priority(2) + weight(2) + port(2) + encoded hostname
    std::vector<std::byte> rdata_srv;
    push_u16_be(rdata_srv, info.priority);
    push_u16_be(rdata_srv, info.weight);
    push_u16_be(rdata_srv, info.port);
    rdata_srv.insert(rdata_srv.end(), name_host.begin(), name_host.end());
    records.push_back({name_service, dns_type::srv, std::move(rdata_srv)});

    records.push_back({name_service, dns_type::txt, encode_txt_records(info.txt_records)});

    if(info.address_ipv4.has_value())
    {
        if(auto enc = encode_ipv4(*info.address_ipv4); enc.has_value())
            records.push_back({name_host, dns_type::a, std::move(*enc)});
    }
    if(info.address_ipv6.has_value())
    {
        if(auto enc = encode_ipv6(*info.address_ipv6); enc.has_value())
            records.push_back({name_host, dns_type::aaaa, std::move(*enc)});
    }

    return records;
}

// Builds an mDNS probe query per RFC 6762 section 8.1:
//   - Header: id=0 (RFC 6762 section 18.1), flags=0x0000 (query)
//   - Questions: service_name and hostname, QTYPE=ANY (0x00FF), QCLASS=IN|QU
//     (all proposed unique names are probed)
//   - Authority: the full proposed record set (SRV + TXT + A/AAAA) for
//     simultaneous probe tiebreaking (RFC 6762 section 8.2.1)
inline std::vector<std::byte> build_probe_query(const service_info &info,
                                                uint32_t probe_authority_ttl = 120)
{
    auto name_service = encode_dns_name(info.service_name);
    auto name_host = encode_dns_name(info.hostname);

    if(name_service.empty() || name_host.empty())
        return {};

    auto proposed = build_proposed_records(info);
    if(proposed.empty())
        return {};

    std::vector<std::byte> packet;
    packet.reserve(12 + name_service.size() + name_host.size() + 8 + proposed.size() * 32);

    // DNS header
    push_u16_be(packet, 0x0000); // id = 0
    push_u16_be(packet, 0x0000); // flags = 0x0000 (standard query)
    push_u16_be(packet, 0x0002); // qdcount = 2 (service_name + hostname)
    push_u16_be(packet, 0x0000); // ancount = 0
    push_u16_be(packet, static_cast<uint16_t>(proposed.size())); // nscount
    push_u16_be(packet, 0x0000); // arcount = 0

    // Question section: service_name then hostname, QTYPE=ANY, QCLASS=IN|QU
    packet.insert(packet.end(), name_service.begin(), name_service.end());
    push_u16_be(packet, detail::to_underlying(dns_type::any)); // QTYPE = ANY (0x00FF)
    push_u16_be(packet, uint16_t{0x8001}); // QCLASS = IN | QU bit
    packet.insert(packet.end(), name_host.begin(), name_host.end());
    push_u16_be(packet, detail::to_underlying(dns_type::any));
    push_u16_be(packet, uint16_t{0x8001});

    // Authority section: the full proposed record set
    for(const auto &rec : proposed)
        append_dns_rr(packet, rec.owner, rec.rtype, probe_authority_ttl, rec.rdata);

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
            append_dns_rr(buf, name, dns_type::ptr, r.ttl, rdata);
        }
        else if constexpr(std::is_same_v<T, record_srv>)
        {
            std::vector<std::byte> rdata;
            push_u16_be(rdata, r.priority);
            push_u16_be(rdata, r.weight);
            push_u16_be(rdata, r.port);
            auto target = encode_dns_name(r.srv_name);
            rdata.insert(rdata.end(), target.begin(), target.end());
            append_dns_rr(buf, name, dns_type::srv, r.ttl, rdata);
        }
        else if constexpr(std::is_same_v<T, record_a>)
        {
            // Encoding failure silently omits the record; the resulting packet
            // stays structurally valid and ancount reflects appended records.
            auto enc = encode_ipv4(r.address_string);
            if(enc.has_value())
                append_dns_rr(buf, name, dns_type::a, r.ttl, *enc);
        }
        else if constexpr(std::is_same_v<T, record_aaaa>)
        {
            auto enc = encode_ipv6(r.address_string);
            if(enc.has_value())
                append_dns_rr(buf, name, dns_type::aaaa, r.ttl, *enc);
        }
        else if constexpr(std::is_same_v<T, record_txt>)
        {
            auto rdata = encode_txt_records(r.entries);
            append_dns_rr(buf, name, dns_type::txt, r.ttl, rdata);
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

// Builds one or more mDNS query packets with known-answer records split across
// packets using the TC (Truncated) bit per RFC 6762 §7.2.
//
// When the accumulated size of known answers would exceed max_payload bytes:
//   - The current packet has its TC bit set (byte 2 |= 0x02)
//   - A new continuation packet is started
//
// RFC 6762 §7.2: continuation packets carry NO questions (qdcount=0) — only
// the first packet contains the question section. The last (or only) packet
// does NOT have the TC bit set. Each packet header's ancount reflects the
// number of answers in that packet.
inline std::vector<std::vector<std::byte>>
build_dns_query_tc(std::string_view name, dns_type qtype,
                   std::span<const mdns_record_variant> known_answers,
                   std::size_t max_payload = 1472,
                   response_mode mode = response_mode::multicast)
{
    std::vector<std::vector<std::byte>> result;

    // Build the base question packet (no answers)
    auto base_pkt = build_dns_query(name, qtype, mode);

    // If there are no known answers, return a single packet directly
    if(known_answers.empty())
    {
        result.push_back(std::move(base_pkt));
        return result;
    }

    // Question-free continuation header per RFC 6762 §7.2.
    auto make_continuation_pkt = []()
    {
        std::vector<std::byte> pkt;
        push_u16_be(pkt, 0x0000); // id
        push_u16_be(pkt, 0x0000); // flags (standard query)
        push_u16_be(pkt, 0x0000); // qdcount = 0 — no questions in continuations
        push_u16_be(pkt, 0x0000); // ancount (patched on flush)
        push_u16_be(pkt, 0x0000); // nscount
        push_u16_be(pkt, 0x0000); // arcount
        return pkt;
    };

    // Measure the size each answer contributes individually
    std::vector<std::pair<std::size_t, std::size_t>> answer_sizes; // (start, end) into a scratch buffer
    std::vector<std::byte> all_answers_buf;
    for(const auto &ka : known_answers)
    {
        std::size_t before = all_answers_buf.size();
        append_known_answer(all_answers_buf, ka);
        answer_sizes.emplace_back(before, all_answers_buf.size());
    }

    auto current_pkt = std::move(base_pkt);
    uint16_t current_ancount = 0;

    for(std::size_t i = 0; i < known_answers.size(); ++i)
    {
        auto [ans_start, ans_end] = answer_sizes[i];
        std::size_t ans_size = ans_end - ans_start;

        // If adding this answer would exceed max_payload, flush current packet first.
        // Always add at least one answer per packet to avoid infinite loops.
        if(current_ancount > 0 && current_pkt.size() + ans_size > max_payload)
        {
            // Set TC bit on current packet (byte 2, bit 1)
            current_pkt[2] = static_cast<std::byte>(
                std::to_integer<uint8_t>(current_pkt[2]) | 0x02u);

            // Update ancount header (bytes 6-7)
            current_pkt[6] = static_cast<std::byte>(static_cast<uint8_t>(current_ancount >> 8));
            current_pkt[7] = static_cast<std::byte>(static_cast<uint8_t>(current_ancount & 0xFF));

            result.push_back(std::move(current_pkt));

            current_pkt = make_continuation_pkt();
            current_ancount = 0;
        }

        // Append this answer to the current packet
        current_pkt.insert(current_pkt.end(),
                           all_answers_buf.data() + ans_start,
                           all_answers_buf.data() + ans_end);
        ++current_ancount;
    }

    // Finalize the last packet (no TC bit)
    current_pkt[6] = static_cast<std::byte>(static_cast<uint8_t>(current_ancount >> 8));
    current_pkt[7] = static_cast<std::byte>(static_cast<uint8_t>(current_ancount & 0xFF));
    result.push_back(std::move(current_pkt));

    return result;
}

}

#endif

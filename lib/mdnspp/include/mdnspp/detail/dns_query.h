#ifndef HPP_GUARD_MDNSPP_DNS_QUERY_H
#define HPP_GUARD_MDNSPP_DNS_QUERY_H

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
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
    append_dns_rr(packet, name_service, dns_type::srv, 120, rdata_srv);

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
            auto rdata = encode_ipv4(r.address_string);
            if(!rdata.empty())
                append_dns_rr(buf, name, dns_type::a, r.ttl, rdata);
        }
        else if constexpr(std::is_same_v<T, record_aaaa>)
        {
            auto rdata = encode_ipv6(r.address_string);
            if(!rdata.empty())
                append_dns_rr(buf, name, dns_type::aaaa, r.ttl, rdata);
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

}

#endif

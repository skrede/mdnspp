#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_QUERY_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_QUERY_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_record_encode.h"

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>

namespace mdnspp::detail {

// RFC 6762 section 18.1: id 0; flags 0 (standard query); no answers or additional records.
inline void append_query_header(std::vector<std::byte> &packet, uint16_t qdcount, uint16_t nscount)
{
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, qdcount);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, nscount);
    push_u16_be(packet, 0x0000);
}

inline void append_question(std::vector<std::byte> &packet, const std::vector<std::byte> &name, dns_type qtype,
                            uint16_t qclass)
{
    packet.insert(packet.end(), name.begin(), name.end());
    push_u16_be(packet, detail::to_underlying(qtype));
    push_u16_be(packet, qclass);
}

inline void set_ancount(std::vector<std::byte> &packet, uint16_t ancount)
{
    packet[6] = static_cast<std::byte>(static_cast<uint8_t>(ancount >> 8));
    packet[7] = static_cast<std::byte>(static_cast<uint8_t>(ancount & 0xFF));
}

// An empty packet means the name failed to encode. The QU bit is bit 15 of QCLASS (RFC 6762 section 5.4).
inline std::vector<std::byte> build_dns_query(std::string_view name, dns_type qtype,
                                              response_mode mode = response_mode::multicast)
{
    std::vector<std::byte> packet;
    packet.reserve(12 + 256 + 4);
    append_query_header(packet, 1, 0);
    auto encoded = encode_dns_name(name);
    if(!encoded.has_value())
        return {};
    append_question(packet, *encoded, qtype, mode == response_mode::unicast ? uint16_t{0x8001} : uint16_t{0x0001});
    return packet;
}

// The proposed unique record set of a probe, used for tiebreaking (RFC 6762 section 8.2.1).
struct proposed_record
{
    std::vector<std::byte> owner;
    dns_type rtype{dns_type::none};
    std::vector<std::byte> rdata;
};

inline void append_proposed_addresses(std::vector<proposed_record> &records, const service_info &info,
                                      const std::vector<std::byte> &host)
{
    if(info.address_ipv4.has_value())
    {
        if(auto enc = encode_ipv4(*info.address_ipv4); enc.has_value())
            records.push_back({host, dns_type::a, std::move(*enc)});
    }
    if(info.address_ipv6.has_value())
    {
        if(auto enc = encode_ipv6(*info.address_ipv6); enc.has_value())
            records.push_back({host, dns_type::aaaa, std::move(*enc)});
    }
}

// Empty when a name fails to encode; an address that fails to encode only omits its record (the caller validates
// and reports addresses separately).
inline std::vector<proposed_record> build_proposed_records(const service_info &info)
{
    auto name_service = encode_dns_name(info.service_name);
    auto name_host = encode_dns_name(info.hostname);
    if(!name_service.has_value() || !name_host.has_value())
        return {};
    std::vector<proposed_record> records;
    records.reserve(4);
    records.push_back(
        {*name_service, dns_type::srv, encode_srv_rdata(info.priority, info.weight, info.port, *name_host)});
    records.push_back({*name_service, dns_type::txt, encode_txt_records(info.txt_records)});
    append_proposed_addresses(records, info, *name_host);
    return records;
}

// RFC 6762 section 8.1: every proposed unique name is asked with QTYPE ANY and the QU bit; the Authority section
// carries the full proposed record set for simultaneous-probe tiebreaking (section 8.2.1).
inline std::vector<std::byte> build_probe_query(const service_info &info,
                                                uint32_t probe_authority_ttl = 120)
{
    auto name_service = encode_dns_name(info.service_name);
    auto name_host = encode_dns_name(info.hostname);
    if(!name_service.has_value() || !name_host.has_value())
        return {};
    auto proposed = build_proposed_records(info);
    if(proposed.empty())
        return {};
    std::vector<std::byte> packet;
    packet.reserve(12 + name_service->size() + name_host->size() + 8 + proposed.size() * 32);
    append_query_header(packet, 2, static_cast<uint16_t>(proposed.size()));
    append_question(packet, *name_service, dns_type::any, uint16_t{0x8001});
    append_question(packet, *name_host, dns_type::any, uint16_t{0x8001});
    for(const auto &rec : proposed)
        append_dns_rr(packet, rec.owner, rec.rtype, probe_authority_ttl, rec.rdata);
    return packet;
}

// Known answers go in the Answer section (RFC 6762 section 7.1); ancount counts the records actually encoded.
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
    set_ancount(packet, ancount);
    return packet;
}

}

#endif

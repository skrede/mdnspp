#ifndef HPP_GUARD_MDNSPP_DNS_FRAME_H
#define HPP_GUARD_MDNSPP_DNS_FRAME_H

#include "mdnspp/parse.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

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
        meta.cache_flush = (rclass & 0x8000) != 0;
        meta.rclass = static_cast<dns_class>(rclass & 0x7FFF);
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

}

#endif

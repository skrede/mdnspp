#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_FRAME_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_FRAME_H

#include "mdnspp/parse.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <type_traits>

namespace mdnspp::detail {

/// Message section a resource record was carried in (RFC 1035 §4.1).
enum class dns_section : uint8_t
{
    answer,
    authority,
    additional,
};

/// Decoded DNS message header (RFC 1035 §4.1.1).
struct dns_frame_header
{
    uint16_t id{0};
    uint16_t flags{0};
    uint16_t qdcount{0};
    uint16_t ancount{0};
    uint16_t nscount{0};
    uint16_t arcount{0};

    /// QR bit -- true for response messages, false for queries.
    [[nodiscard]] constexpr bool is_response() const noexcept
    {
        return (flags & 0x8000U) != 0;
    }
};

// Walks a DNS frame, calling on_record for each successfully parsed resource
// record. Silently skips malformed records.
//
// Template parameter Callback is either of:
//   - void(mdns_record_variant)
//   - void(mdns_record_variant, const dns_frame_header &, dns_section)
//
// The three-argument form exposes the message header (QR flag, counts) and the
// section each record was carried in, so consumers can distinguish answers in
// responses from known-answer/Authority records in query packets
// (RFC 6762 §7.1, §8.2).
template <typename Callback>
void walk_dns_frame(std::span<const std::byte> data, const endpoint &sender, Callback &&on_record)
{
    // Need at least 12 bytes for DNS header
    if(data.size() < 12)
        return;

    const std::byte *buf = data.data();

    dns_frame_header header;
    header.id = read_u16_be(buf);
    header.flags = read_u16_be(buf + 2);
    header.qdcount = read_u16_be(buf + 4);
    header.ancount = read_u16_be(buf + 6);
    header.nscount = read_u16_be(buf + 8);
    header.arcount = read_u16_be(buf + 10);

    size_t offset = 12;

    // Skip questions section (name + qtype(2) + qclass(2))
    for(uint16_t i = 0; i < header.qdcount; ++i)
    {
        if(!skip_dns_name(data, offset))
            return;
        offset += 4; // qtype + qclass
        if(offset > data.size())
            return;
    }

    // Parse RRs: answer + authority + additional
    uint32_t rr_total = static_cast<uint32_t>(header.ancount) +
        static_cast<uint32_t>(header.nscount) +
        static_cast<uint32_t>(header.arcount);

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

        dns_section section = rr < header.ancount
            ? dns_section::answer
            : (rr < static_cast<uint32_t>(header.ancount) + header.nscount
                   ? dns_section::authority
                   : dns_section::additional);

        // Attempt to parse the record; silently skip on failure
        auto result = parse::record(data, meta);
        if(result.has_value())
        {
            if constexpr(std::is_invocable_v<Callback &, mdns_record_variant,
                                             const dns_frame_header &, dns_section>)
                on_record(std::move(*result), std::as_const(header), section);
            else
                on_record(std::move(*result));
        }

        // Advance past rdata regardless of parse success
        offset = record_offset + record_length;
    }
}

}

#endif

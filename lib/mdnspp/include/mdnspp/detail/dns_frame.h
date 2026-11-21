#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_FRAME_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_FRAME_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include "mdnspp/parse.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <type_traits>

namespace mdnspp::detail {

// RFC 1035 section 4.1
enum class dns_section : uint8_t
{
    answer,
    authority,
    additional,
};

// RFC 1035 section 4.1.1
struct dns_frame_header
{
    uint16_t id{0};
    uint16_t flags{0};
    uint16_t qdcount{0};
    uint16_t ancount{0};
    uint16_t nscount{0};
    uint16_t arcount{0};

    constexpr bool is_response() const noexcept
    {
        return (flags & 0x8000U) != 0;
    }
};

inline dns_frame_header read_frame_header(std::span<const std::byte> data)
{
    const std::byte *buf = data.data();
    dns_frame_header header;
    header.id = read_u16_be(buf);
    header.flags = read_u16_be(buf + 2);
    header.qdcount = read_u16_be(buf + 4);
    header.ancount = read_u16_be(buf + 6);
    header.nscount = read_u16_be(buf + 8);
    header.arcount = read_u16_be(buf + 10);
    return header;
}

inline bool skip_questions(std::span<const std::byte> data, size_t &offset, uint16_t qdcount)
{
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        if(!skip_dns_name(data, offset))
            return false;
        offset += 4; // qtype + qclass
        if(offset > data.size())
            return false;
    }
    return true;
}

inline dns_section frame_section(const dns_frame_header &header, uint32_t rr)
{
    return rr < header.ancount
        ? dns_section::answer
        : (rr < static_cast<uint32_t>(header.ancount) + header.nscount
               ? dns_section::authority
               : dns_section::additional);
}

// Empty when the name, the fixed fields (type, class, TTL, RDLENGTH: 10 bytes) or the rdata run past the frame.
inline std::optional<record_metadata> read_record_metadata(std::span<const std::byte> data, size_t offset,
                                                           const endpoint &sender)
{
    size_t name_offset = offset;
    if(!skip_dns_name(data, offset))
        return std::nullopt;
    if(offset + 10 > data.size())
        return std::nullopt;
    const std::byte *buf = data.data();
    uint16_t rclass = read_u16_be(buf + offset + 2);
    record_metadata meta;
    meta.sender = sender;
    meta.rtype = static_cast<dns_type>(read_u16_be(buf + offset));
    meta.cache_flush = (rclass & 0x8000) != 0;
    meta.rclass = static_cast<dns_class>(rclass & 0x7FFF);
    meta.ttl = read_u32_be(buf + offset + 4);
    meta.record_length = static_cast<size_t>(read_u16_be(buf + offset + 8));
    meta.name_offset = name_offset;
    meta.record_offset = offset + 10;
    if(meta.record_offset + meta.record_length > data.size())
        return std::nullopt;
    return meta;
}

// A record that fails to parse is skipped silently.
template <typename Callback>
void deliver_record(std::span<const std::byte> data, const record_metadata &meta, const dns_frame_header &header,
                    dns_section section, Callback &on_record)
{
    auto result = parse::record(data, meta);
    if(!result.has_value())
        return;
    if constexpr(std::is_invocable_v<Callback &, mdns_record_variant, const dns_frame_header &, dns_section>)
        on_record(std::move(*result), std::as_const(header), section);
    else
        on_record(std::move(*result));
}

// on_record takes (mdns_record_variant) or (mdns_record_variant, const dns_frame_header &, dns_section); the
// second form tells response answers from query known-answer and Authority records (RFC 6762 sections 7.1, 8.2).
template <typename Callback>
void walk_dns_frame(std::span<const std::byte> data, const endpoint &sender, Callback &&on_record)
{
    if(data.size() < 12)
        return;
    dns_frame_header header = read_frame_header(data);
    size_t offset = 12;
    if(!skip_questions(data, offset, header.qdcount))
        return;
    uint32_t rr_total = static_cast<uint32_t>(header.ancount) +
        static_cast<uint32_t>(header.nscount) +
        static_cast<uint32_t>(header.arcount);
    for(uint32_t rr = 0; rr < rr_total; ++rr)
    {
        auto meta = read_record_metadata(data, offset, sender);
        if(!meta.has_value())
            return;
        deliver_record(data, *meta, header, frame_section(header, rr), on_record);
        offset = meta->record_offset + meta->record_length;
    }
}

}

#endif

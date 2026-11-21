#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_TIEBREAK_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_TIEBREAK_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <vector>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>

namespace mdnspp::detail {

// RFC 6762 §8.2.1 orders records by class, then type, then rdata bytes; the defaulted comparison follows the
// member order.
struct tiebreak_record
{
    uint16_t rclass{1};
    uint16_t rtype{0};
    std::vector<std::byte> rdata;

    friend std::strong_ordering operator<=>(const tiebreak_record &, const tiebreak_record &) = default;
};

inline bool skip_tiebreak_questions(std::span<const std::byte> data, std::size_t &offset, uint16_t qdcount)
{
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        if(!skip_dns_name(data, offset)) return false;
        if(offset + 4 > data.size()) return false;
        offset += 4;
    }
    return true;
}

inline bool skip_tiebreak_answers(std::span<const std::byte> data, std::size_t &offset, uint16_t ancount)
{
    for(uint16_t i = 0; i < ancount; ++i)
    {
        if(!skip_dns_name(data, offset)) return false;
        if(offset + 10 > data.size()) return false;
        offset += 8;
        uint16_t rdlen = read_u16_be(data.data() + offset);
        offset += 2;
        if(offset + rdlen > data.size()) return false;
        offset += rdlen;
    }
    return true;
}

inline std::optional<std::vector<std::byte>> uncompressed_name(std::span<const std::byte> data, std::size_t offset)
{
    auto target = read_dns_name(data, offset);
    if(!target.has_value()) return std::nullopt;
    auto encoded = encode_dns_name(*target);
    if(!encoded.has_value()) return std::nullopt;
    return std::move(*encoded);
}

// RFC 6762 §8.2.1 compares uncompressed rdata, so the SRV and PTR targets are decompressed and re-encoded.
inline std::optional<std::vector<std::byte>>
canonical_rdata(std::span<const std::byte> data, std::size_t offset, uint16_t rtype, uint16_t rdlen)
{
    std::vector<std::byte> rdata;
    if(rtype == to_underlying(dns_type::srv) && rdlen >= 6)
    {
        rdata.assign(data.data() + offset, data.data() + offset + 6);
        auto encoded = uncompressed_name(data, offset + 6);
        if(!encoded.has_value()) return std::nullopt;
        rdata.insert(rdata.end(), encoded->begin(), encoded->end());
    }
    else if(rtype == to_underlying(dns_type::ptr))
    {
        auto encoded = uncompressed_name(data, offset);
        if(!encoded.has_value()) return std::nullopt;
        rdata = std::move(*encoded);
    }
    else
    {
        rdata.assign(data.data() + offset, data.data() + offset + rdlen);
    }
    return rdata;
}

// The class is compared without the cache-flush bit (RFC 6762 §8.2.1).
inline std::optional<tiebreak_record> read_authority_record(std::span<const std::byte> data, std::size_t &offset)
{
    if(!skip_dns_name(data, offset)) return std::nullopt;
    if(offset + 10 > data.size()) return std::nullopt;
    uint16_t rtype = read_u16_be(data.data() + offset);
    uint16_t rclass = static_cast<uint16_t>(read_u16_be(data.data() + offset + 2) & 0x7FFFu);
    offset += 8;
    uint16_t rdlen = read_u16_be(data.data() + offset);
    offset += 2;
    if(offset + rdlen > data.size()) return std::nullopt;

    auto rdata = canonical_rdata(data, offset, rtype, rdlen);
    if(!rdata.has_value()) return std::nullopt;
    offset += rdlen;
    return tiebreak_record{rclass, rtype, std::move(*rdata)};
}

inline std::vector<tiebreak_record> extract_authority_records(std::span<const std::byte> data)
{
    if(data.size() < 12)
        return {};

    uint16_t qdcount = read_u16_be(data.data() + 4);
    uint16_t ancount = read_u16_be(data.data() + 6);
    uint16_t nscount = read_u16_be(data.data() + 8);

    if(nscount == 0)
        return {};

    std::size_t offset = 12;
    if(!skip_tiebreak_questions(data, offset, qdcount) || !skip_tiebreak_answers(data, offset, ancount))
        return {};

    std::vector<tiebreak_record> records;
    records.reserve(nscount);
    for(uint16_t i = 0; i < nscount; ++i)
    {
        auto record = read_authority_record(data, offset);
        if(!record.has_value()) return {};
        records.push_back(std::move(*record));
    }
    return records;
}

// RFC 6762 §8.2.1 over full record sets: when one sorted set is a prefix of the other, the longer set wins.
// Returns < 0 when ours loses and > 0 when it wins; 0 means identical data, which is not a conflict.
inline int32_t compare_record_sets(std::vector<tiebreak_record> ours,
                                   std::vector<tiebreak_record> theirs)
{
    std::sort(ours.begin(), ours.end());
    std::sort(theirs.begin(), theirs.end());

    auto count = (std::min)(ours.size(), theirs.size());
    for(std::size_t i = 0; i < count; ++i)
    {
        auto cmp = ours[i] <=> theirs[i];
        if(cmp < 0) return -1;
        if(cmp > 0) return 1;
    }
    if(ours.size() < theirs.size()) return -1;
    if(ours.size() > theirs.size()) return 1;
    return 0;
}

}

#endif

#ifndef HPP_GUARD_MDNSPP_SERVER_DETAIL_RESPONSE_HELPERS_H
#define HPP_GUARD_MDNSPP_SERVER_DETAIL_RESPONSE_HELPERS_H

#include "helpers.h"

#include "mdnspp/dns_name.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/byte_order.h"

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>

struct parsed_rr
{
    std::string name;
    uint16_t rtype;
    uint16_t rclass;
    uint32_t ttl;
    std::vector<std::byte> rdata;
    bool in_answer_section;
};

inline bool skip_questions(std::span<const std::byte> pkt, uint16_t qdcount, std::size_t &offset)
{
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        if(!skip_dns_name(pkt, offset))
            return false;
        offset += 4;
    }
    return true;
}

inline std::optional<parsed_rr> read_rr(std::span<const std::byte> pkt, std::size_t &offset, bool in_answer_section)
{
    auto name = read_dns_name(pkt, offset);
    if(!name.has_value() || !skip_dns_name(pkt, offset))
        return std::nullopt;
    if(offset + 10 > pkt.size())
        return std::nullopt;
    const std::byte *fields = pkt.data() + offset;
    uint16_t rdlen = read_u16_be(fields + 8);
    offset += 10;
    if(offset + rdlen > pkt.size())
        return std::nullopt;
    parsed_rr rr{.name = *name,
                 .rtype = read_u16_be(fields),
                 .rclass = read_u16_be(fields + 2),
                 .ttl = read_u32_be(fields + 4),
                 .rdata = std::vector<std::byte>(pkt.data() + offset, pkt.data() + offset + rdlen),
                 .in_answer_section = in_answer_section};
    offset += rdlen;
    return rr;
}

inline std::vector<parsed_rr> collect_rrs(const std::vector<std::byte> &pkt)
{
    std::vector<parsed_rr> rrs;
    if(pkt.size() < 12)
        return rrs;
    uint16_t ancount = read_u16_be(pkt.data() + 6);
    uint32_t total = static_cast<uint32_t>(ancount) + read_u16_be(pkt.data() + 8) + read_u16_be(pkt.data() + 10);
    std::size_t offset = 12;
    if(!skip_questions(pkt, read_u16_be(pkt.data() + 4), offset))
        return rrs;
    for(uint32_t i = 0; i < total; ++i)
    {
        auto rr = read_rr(pkt, offset, i < ancount);
        if(!rr.has_value())
            break;
        rrs.push_back(std::move(*rr));
    }
    return rrs;
}

inline const parsed_rr *find_rr(const std::vector<parsed_rr> &rrs, dns_type t, std::string_view name = {})
{
    for(const auto &rr : rrs)
    {
        if(rr.rtype != to_underlying(t))
            continue;
        if(!name.empty() && dns_name{rr.name} != dns_name{name})
            continue;
        return &rr;
    }
    return nullptr;
}

#endif

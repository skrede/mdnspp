#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_KNOWN_ANSWER_RECORD_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_KNOWN_ANSWER_RECORD_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_write.h"

#include "mdnspp/service_info.h"

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>

namespace mdnspp::detail {

struct own_rdata
{
    std::vector<std::byte> txt;
    std::vector<std::byte> a;
    std::vector<std::byte> aaaa;
};

inline own_rdata encode_own_rdata(const service_info &info)
{
    own_rdata ours{encode_txt_records(info.txt_records), {}, {}};
    if(info.address_ipv4.has_value())
    {
        if(auto enc = encode_ipv4(*info.address_ipv4); enc.has_value())
            ours.a = std::move(*enc);
    }
    if(info.address_ipv6.has_value())
    {
        if(auto enc = encode_ipv6(*info.address_ipv6); enc.has_value())
            ours.aaaa = std::move(*enc);
    }
    return ours;
}

struct known_answer
{
    std::string name;
    dns_type rtype;
    uint16_t rclass;
    uint32_t ttl;
    std::size_t rdata_offset;
    uint16_t rdlength;
};

// No value where the walk stops: an unreadable name, or fixed fields or rdata past the end of the packet.
inline std::optional<known_answer> read_known_answer(std::span<const std::byte> data, std::size_t &offset)
{
    auto name_result = read_dns_name(data, offset);
    if(!name_result.has_value() || !skip_dns_name(data, offset))
        return std::nullopt;
    if(offset + 10 > data.size())
        return std::nullopt;
    const std::byte *buf = data.data();
    dns_type rtype = static_cast<dns_type>(read_u16_be(buf + offset));
    offset += 2;
    uint16_t rclass = static_cast<uint16_t>(read_u16_be(buf + offset) & 0x7FFFu);
    offset += 2;
    uint32_t ttl = read_u32_be(buf + offset);
    offset += 4;
    uint16_t rdlength = read_u16_be(buf + offset);
    offset += 2;
    std::size_t rdata_offset = offset;
    offset += rdlength;
    if(offset > data.size())
        return std::nullopt;
    return known_answer{std::move(*name_result), rtype, rclass, ttl, rdata_offset, rdlength};
}

inline bool rdata_equals(std::span<const std::byte> rdata, const std::vector<std::byte> &ours)
{
    return !ours.empty() && rdata.size() == ours.size() && std::equal(rdata.begin(), rdata.end(), ours.begin());
}

}

#endif

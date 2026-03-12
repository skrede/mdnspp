#ifndef HPP_GUARD_MDNSPP_SERVER_QUERY_MATCH_H
#define HPP_GUARD_MDNSPP_SERVER_QUERY_MATCH_H

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <string>
#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <string_view>

namespace mdnspp::detail {

static constexpr std::string_view meta_query_name{"_services._dns-sd._udp.local."};

struct query_match_result
{
    dns_type accumulated_qtype{dns_type::none};
    response_mode mode{response_mode::unicast};
    bool any_matched{false};
    bool needs_nsec{false};
    bool meta_matched{false};
    std::string matched_subtype;
    size_t offset_after_questions{0};
};

inline bool query_name_matches(std::span<const std::byte> data, size_t name_start, size_t name_end,
                               const service_info &info)
{
    auto qname = data.subspan(name_start, name_end - name_start);
    auto match = [&](std::string_view name)
    {
        auto encoded = encode_dns_name(name);
        return std::ranges::equal(qname, std::span<const std::byte>(encoded));
    };
    return match(info.service_type)
        || match(info.service_name)
        || match(info.hostname);
}

inline bool matches_meta_query(std::span<const std::byte> data, size_t name_start, size_t name_end)
{
    auto qname = data.subspan(name_start, name_end - name_start);
    auto encoded = encode_dns_name(meta_query_name);
    return std::ranges::equal(qname, std::span<const std::byte>(encoded));
}

inline std::string_view matches_subtype_query(std::span<const std::byte> data, size_t name_start,
                                              size_t name_end, const service_info &info)
{
    auto qname = data.subspan(name_start, name_end - name_start);
    for(const auto &sub : info.subtypes)
    {
        auto subtype_name = sub + "._sub." + info.service_type.str();
        auto encoded = encode_dns_name(subtype_name);
        if(std::ranges::equal(qname, std::span<const std::byte>(encoded)))
            return sub;
    }
    return {};
}

inline bool has_record_type(dns_type qtype, const service_info &info)
{
    switch(qtype)
    {
    case dns_type::a:    return info.address_ipv4.has_value();
    case dns_type::aaaa: return info.address_ipv6.has_value();
    case dns_type::ptr:
    case dns_type::srv:
    case dns_type::txt:  return true;
    case dns_type::any:  return true;
    default:             return false;
    }
}

inline query_match_result match_queries(std::span<const std::byte> data,
                                        const service_info &info,
                                        const service_options &opts)
{
    query_match_result result;

    if(data.size() < 12)
        return result;

    const std::byte *buf = data.data();
    uint16_t qdcount = read_u16_be(buf + 4);
    if(qdcount == 0)
        return result;

    size_t offset = 12;
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        size_t name_start = offset;
        if(!skip_dns_name(data, offset))
            break;
        size_t name_end = offset;

        if(offset + 4 > data.size())
            break;

        dns_type qtype = static_cast<dns_type>(read_u16_be(buf + offset));
        uint16_t qclass = read_u16_be(buf + offset + 2);
        offset += 4;

        if(opts.respond_to_meta_queries && qtype == dns_type::ptr &&
           matches_meta_query(data, name_start, name_end))
        {
            result.meta_matched = true;
            if((qclass & 0x8000) == 0)
                result.mode = response_mode::multicast;
            continue;
        }

        if(qtype == dns_type::ptr)
        {
            auto sub = matches_subtype_query(data, name_start, name_end, info);
            if(!sub.empty())
            {
                result.matched_subtype = sub;
                if((qclass & 0x8000) == 0)
                    result.mode = response_mode::multicast;
                continue;
            }
        }

        if(!query_name_matches(data, name_start, name_end, info))
            continue;

        if(!result.any_matched)
        {
            result.accumulated_qtype = qtype;
            result.any_matched = true;
        }
        else if(result.accumulated_qtype != qtype)
        {
            result.accumulated_qtype = dns_type::any;
        }

        if(qtype != dns_type::any && !has_record_type(qtype, info))
            result.needs_nsec = true;

        if((qclass & 0x8000) == 0)
            result.mode = response_mode::multicast;
    }

    result.offset_after_questions = offset;
    return result;
}

}

#endif

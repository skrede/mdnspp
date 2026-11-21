#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_QUERY_MATCH_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_QUERY_MATCH_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_question_section.h"

#include "mdnspp/dns_name.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

namespace mdnspp::detail {

static constexpr std::string_view meta_query_name{"_services._dns-sd._udp.local."};

enum class owned_name : uint8_t
{
    service_type,
    service_name,
    hostname,
};

struct question_match
{
    owned_name target{owned_name::service_type};
    dns_type qtype{dns_type::none};
};

struct query_match_result
{
    std::vector<question_match> matched;
    dns_type accumulated_qtype{dns_type::none};
    response_mode mode{response_mode::unicast};
    bool any_matched{false};
    bool meta_matched{false};
    std::string matched_subtype;
    size_t offset_after_questions{0};
    uint16_t query_id{0};
};

inline bool query_name_matches(std::span<const std::byte> data, size_t name_start,
                               const service_info &info)
{
    // RFC 1035 section 3.1: labels compare case-insensitively.
    auto decoded = read_dns_name(data, name_start);
    if(!decoded.has_value())
        return false;
    dns_name qname{*decoded};
    return qname == info.service_type
        || qname == info.service_name
        || qname == info.hostname;
}

inline bool matches_meta_query(std::span<const std::byte> data, size_t name_start)
{
    auto decoded = read_dns_name(data, name_start);
    if(!decoded.has_value())
        return false;
    return dns_name{*decoded} == dns_name{meta_query_name};
}

inline std::string_view matches_subtype_query(std::span<const std::byte> data, size_t name_start,
                                              const service_info &info)
{
    auto decoded = read_dns_name(data, name_start);
    if(!decoded.has_value())
        return {};
    dns_name qname{*decoded};
    for(const auto &sub : info.subtypes)
    {
        auto subtype_name = sub + "._sub." + info.service_type.str();
        if(qname == dns_name{subtype_name})
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

inline std::optional<owned_name> classify_owned_name(std::span<const std::byte> data, std::size_t name_start,
                                                     const service_info &info)
{
    auto decoded = read_dns_name(data, name_start);
    if(!decoded.has_value())
        return std::nullopt;
    dns_name qname{*decoded};
    if(qname == info.service_type)
        return owned_name::service_type;
    if(qname == info.service_name)
        return owned_name::service_name;
    if(qname == info.hostname)
        return owned_name::hostname;
    return std::nullopt;
}

// A question without the QU bit (top bit of QCLASS) asks for a multicast response (RFC 6762 section 5.4).
inline void note_response_mode(query_match_result &result, uint16_t qclass)
{
    if((qclass & 0x8000) == 0)
        result.mode = response_mode::multicast;
}

inline void accumulate_match(query_match_result &result, owned_name target, const parsed_question &q)
{
    result.matched.push_back(question_match{target, q.qtype});
    if(!result.any_matched)
    {
        result.accumulated_qtype = q.qtype;
        result.any_matched = true;
    }
    else if(result.accumulated_qtype != q.qtype)
    {
        result.accumulated_qtype = dns_type::any;
    }
    note_response_mode(result, q.qclass);
}

// Meta-query and subtype questions are recorded on their own and never reach the owned-name match.
inline bool match_enumeration_question(query_match_result &result, std::span<const std::byte> data,
                                       const parsed_question &q, const service_info &info,
                                       const service_options &opts)
{
    if(opts.respond_to_meta_queries && q.qtype == dns_type::ptr && matches_meta_query(data, q.name_start))
    {
        result.meta_matched = true;
        note_response_mode(result, q.qclass);
        return true;
    }
    if(q.qtype != dns_type::ptr)
        return false;
    auto sub = matches_subtype_query(data, q.name_start, info);
    if(sub.empty())
        return false;
    result.matched_subtype = sub;
    note_response_mode(result, q.qclass);
    return true;
}

inline query_match_result match_queries(std::span<const std::byte> data, const service_info &info,
                                        const service_options &opts)
{
    query_match_result result;
    if(data.size() < 12)
        return result;
    result.query_id = read_u16_be(data.data());
    uint16_t qdcount = read_u16_be(data.data() + 4);
    if(qdcount == 0)
        return result;
    std::size_t offset = 12;
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        auto q = read_question(data, offset);
        if(!q.has_value())
            break;
        if(match_enumeration_question(result, data, *q, info, opts))
            continue;
        if(auto target = classify_owned_name(data, q->name_start, info); target.has_value())
            accumulate_match(result, *target, *q);
    }
    result.offset_after_questions = offset;
    return result;
}

}

#endif

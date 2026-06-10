#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_QUERY_MATCH_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_QUERY_MATCH_H

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>

namespace mdnspp::detail {

static constexpr std::string_view meta_query_name{"_services._dns-sd._udp.local."};

// Which of the service's owned names a question targets.
enum class owned_name : uint8_t
{
    service_type,
    service_name,
    hostname,
};

// One matched question with its name<->qtype pairing preserved (RFC 6762 §6:
// each question is answered with the records owned by THAT name and of THAT
// qtype).
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
    // Decode the query name and compare via dns_name for case-insensitive,
    // FQDN-normalized matching (RFC 1035 s3.1: labels are case-insensitive).
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

inline query_match_result match_queries(std::span<const std::byte> data,
                                        const service_info &info,
                                        const service_options &opts)
{
    query_match_result result;

    if(data.size() < 12)
        return result;

    const std::byte *buf = data.data();
    result.query_id = read_u16_be(buf);
    uint16_t qdcount = read_u16_be(buf + 4);
    if(qdcount == 0)
        return result;

    size_t offset = 12;
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        size_t name_start = offset;
        if(!skip_dns_name(data, offset))
            break;

        if(offset + 4 > data.size())
            break;

        dns_type qtype = static_cast<dns_type>(read_u16_be(buf + offset));
        uint16_t qclass = read_u16_be(buf + offset + 2);
        offset += 4;

        if(opts.respond_to_meta_queries && qtype == dns_type::ptr &&
           matches_meta_query(data, name_start))
        {
            result.meta_matched = true;
            if((qclass & 0x8000) == 0)
                result.mode = response_mode::multicast;
            continue;
        }

        if(qtype == dns_type::ptr)
        {
            auto sub = matches_subtype_query(data, name_start, info);
            if(!sub.empty())
            {
                result.matched_subtype = sub;
                if((qclass & 0x8000) == 0)
                    result.mode = response_mode::multicast;
                continue;
            }
        }

        auto decoded = read_dns_name(data, name_start);
        if(!decoded.has_value())
            continue;
        dns_name qname{*decoded};

        owned_name target;
        if(qname == info.service_type)
            target = owned_name::service_type;
        else if(qname == info.service_name)
            target = owned_name::service_name;
        else if(qname == info.hostname)
            target = owned_name::hostname;
        else
            continue;

        result.matched.push_back(question_match{target, qtype});

        if(!result.any_matched)
        {
            result.accumulated_qtype = qtype;
            result.any_matched = true;
        }
        else if(result.accumulated_qtype != qtype)
        {
            result.accumulated_qtype = dns_type::any;
        }

        if((qclass & 0x8000) == 0)
            result.mode = response_mode::multicast;
    }

    result.offset_after_questions = offset;
    return result;
}

// Re-encodes the question section of a query packet without compression
// pointers. Used for legacy unicast responses, which MUST repeat the question
// (RFC 6762 §6.7). Returns the encoded section and the question count;
// empty section with count 0 on malformed input.
inline std::pair<std::vector<std::byte>, uint16_t>
rebuild_question_section(std::span<const std::byte> data)
{
    if(data.size() < 12)
        return {};

    uint16_t qdcount = read_u16_be(data.data() + 4);
    std::vector<std::byte> section;
    uint16_t rebuilt = 0;

    size_t offset = 12;
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        auto decoded = read_dns_name(data, offset);
        if(!decoded.has_value() || !skip_dns_name(data, offset))
            break;
        if(offset + 4 > data.size())
            break;

        auto encoded = encode_dns_name(*decoded);
        if(encoded.empty())
            break;

        uint16_t qtype = read_u16_be(data.data() + offset);
        // QU bit (top bit of qclass) is meaningless in a response; clear it.
        uint16_t qclass = static_cast<uint16_t>(read_u16_be(data.data() + offset + 2) & 0x7FFFu);
        offset += 4;

        section.insert(section.end(), encoded.begin(), encoded.end());
        push_u16_be(section, qtype);
        push_u16_be(section, qclass);
        ++rebuilt;
    }

    return {std::move(section), rebuilt};
}

}

#endif

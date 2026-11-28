#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_ENUMERATION_MATCH_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_ENUMERATION_MATCH_H

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_question_section.h"

#include "mdnspp/dns_name.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include <span>
#include <string>
#include <cstddef>
#include <optional>
#include <string_view>

namespace mdnspp::detail {

static constexpr std::string_view meta_query_name{"_services._dns-sd._udp.local."};

struct enumeration_match
{
    bool meta{false};
    std::string_view subtype;
};

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

// Meta-query and subtype questions are recorded on their own and never reach the owned-name match.
inline std::optional<enumeration_match> match_enumeration_question(std::span<const std::byte> data,
                                                                   const parsed_question &q,
                                                                   const service_info &info,
                                                                   const service_options &opts)
{
    if(q.qtype != dns_type::ptr)
        return std::nullopt;
    if(opts.respond_to_meta_queries && matches_meta_query(data, q.name_start))
        return enumeration_match{.meta = true, .subtype = {}};
    auto sub = matches_subtype_query(data, q.name_start, info);
    if(sub.empty())
        return std::nullopt;
    return enumeration_match{.meta = false, .subtype = sub};
}

}

#endif

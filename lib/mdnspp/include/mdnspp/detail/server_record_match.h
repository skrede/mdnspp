#ifndef HPP_GUARD_MDNSPP_DETAIL_SERVER_RECORD_MATCH_H
#define HPP_GUARD_MDNSPP_DETAIL_SERVER_RECORD_MATCH_H

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/service_info.h"

#include <string>
#include <cstddef>
#include <variant>
#include <optional>
#include <type_traits>

namespace mdnspp::detail {

inline bool ptr_matches_ours(const record_ptr &r, const service_info &info)
{
    return r.name == info.service_type && r.ptr_name == info.service_name;
}

inline bool srv_matches_ours(const record_srv &r, const service_info &info)
{
    return r.name == info.service_name
        && r.port == info.port
        && r.weight == info.weight
        && r.priority == info.priority
        && r.srv_name == info.hostname;
}

// Empty service_txt entries encode to zero-length strings, which parse::txt ignores (RFC 6763 section 6.4), so
// they are skipped on our side and an effectively empty TXT compares equal.
inline bool txt_matches_ours(const record_txt &r, const service_info &info)
{
    if(r.name != info.service_name)
        return false;
    auto is_empty = [](const service_txt &e) { return e.key.empty() && !e.value.has_value(); };
    std::size_t i = 0;
    std::size_t j = 0;
    while(true)
    {
        while(j < info.txt_records.size() && is_empty(info.txt_records[j])) ++j;
        if(i == r.entries.size() || j == info.txt_records.size())
            break;
        if(r.entries[i].key != info.txt_records[j].key
           || r.entries[i].value != info.txt_records[j].value)
            return false;
        ++i;
        ++j;
    }
    return i == r.entries.size() && j == info.txt_records.size();
}

inline bool address_matches_ours(const dns_name &name, const std::string &address,
                                 const std::optional<std::string> &ours, const service_info &info)
{
    return name == info.hostname
        && ours.has_value()
        && address == *ours;
}

// RFC 6762 section 7.1: a record is ours only when owner name, type-specific ownership and rdata all match.
inline bool record_matches_ours(const mdns_record_variant &rec, const service_info &info)
{
    return std::visit([&](const auto &r) -> bool
    {
        using T = std::decay_t<decltype(r)>;
        if constexpr(std::is_same_v<T, record_ptr>)
            return ptr_matches_ours(r, info);
        else if constexpr(std::is_same_v<T, record_srv>)
            return srv_matches_ours(r, info);
        else if constexpr(std::is_same_v<T, record_txt>)
            return txt_matches_ours(r, info);
        else if constexpr(std::is_same_v<T, record_a>)
            return address_matches_ours(r.name, r.address_string, info.address_ipv4, info);
        else if constexpr(std::is_same_v<T, record_aaaa>)
            return address_matches_ours(r.name, r.address_string, info.address_ipv6, info);
        else
            return false;
    }, rec);
}

// RFC 6762 section 9: a record claiming one of our unique names (instance or hostname) with different rdata is a
// conflict that requires re-probing. PTR is shared and never conflicts.
inline bool record_conflicts_ours(const mdns_record_variant &rec, const service_info &info)
{
    return std::visit([&](const auto &r) -> bool
    {
        using T = std::decay_t<decltype(r)>;
        if constexpr(std::is_same_v<T, record_ptr>)
        {
            return false;
        }
        else if constexpr(std::is_same_v<T, record_srv> || std::is_same_v<T, record_txt>)
        {
            return r.name == info.service_name && !record_matches_ours(rec, info);
        }
        else if constexpr(std::is_same_v<T, record_a> || std::is_same_v<T, record_aaaa>)
        {
            return r.name == info.hostname && !record_matches_ours(rec, info);
        }
        else
        {
            return false;
        }
    }, rec);
}

}

#endif

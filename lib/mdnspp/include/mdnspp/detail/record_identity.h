#ifndef HPP_GUARD_MDNSPP_DETAIL_RECORD_IDENTITY_H
#define HPP_GUARD_MDNSPP_DETAIL_RECORD_IDENTITY_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/hash_combine.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"

#include <cstddef>
#include <cstdint>
#include <variant>
#include <functional>
#include <type_traits>

namespace mdnspp::detail {

struct record_name_type
{
    dns_name name;
    dns_type type{dns_type::none};
    dns_class rclass{dns_class::in};

    bool operator==(const record_name_type &) const = default;
};

struct record_name_type_hash
{
    std::size_t operator()(const record_name_type &k) const noexcept
    {
        auto h1 = std::hash<dns_name>{}(k.name);
        auto h2 = std::hash<uint16_t>{}(detail::to_underlying(k.type));
        auto h3 = std::hash<uint16_t>{}(detail::to_underlying(k.rclass));
        return hash_combine(hash_combine(h1, h2), h3);
    }
};

inline record_name_type extract_name_type(const mdns_record_variant &rec)
{
    return std::visit([](const auto &r) -> record_name_type {
        return {r.name, std::remove_cvref_t<decltype(r)>::rtype, r.rclass};
    }, rec);
}

inline uint32_t extract_ttl(const mdns_record_variant &rec)
{
    return std::visit([](const auto &r) { return r.ttl; }, rec);
}

inline bool extract_cache_flush(const mdns_record_variant &rec)
{
    return std::visit([](const auto &r) { return r.cache_flush; }, rec);
}

template <typename Record>
bool typed_rdata_equal(const Record &lhs, const Record &rhs)
{
    if constexpr (std::is_same_v<Record, record_a> || std::is_same_v<Record, record_aaaa>)
        return lhs.address_string == rhs.address_string;
    else if constexpr (std::is_same_v<Record, record_ptr>)
        return lhs.ptr_name == rhs.ptr_name;
    else if constexpr (std::is_same_v<Record, record_srv>)
        return lhs.port == rhs.port &&
               lhs.weight == rhs.weight &&
               lhs.priority == rhs.priority &&
               lhs.srv_name == rhs.srv_name;
    else
        return lhs.entries == rhs.entries;
}

inline bool rdata_equal(const mdns_record_variant &a, const mdns_record_variant &b)
{
    if (a.index() != b.index())
        return false;

    return std::visit([](const auto &lhs, const auto &rhs) -> bool {
        using lhs_t = std::remove_cvref_t<decltype(lhs)>;
        using rhs_t = std::remove_cvref_t<decltype(rhs)>;

        if constexpr (std::is_same_v<lhs_t, rhs_t>)
            return typed_rdata_equal(lhs, rhs);
        else
            return false;
    }, a, b);
}

inline bool record_identity_equal(const mdns_record_variant &a, const mdns_record_variant &b)
{
    return extract_name_type(a) == extract_name_type(b) && rdata_equal(a, b);
}

}

#endif

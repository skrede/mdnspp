#ifndef HPP_GUARD_MDNSPP_DETAIL_DNS_ENUMS_H
#define HPP_GUARD_MDNSPP_DETAIL_DNS_ENUMS_H

// dns_enums.h — DNS vocabulary types for mdnspp.
// dns_type and dns_class are exposed in namespace mdnspp (not mdnspp::detail)
// because they appear directly in public API signatures.

#include <cstdint>
#include <string_view>

namespace mdnspp {

enum class dns_type : uint16_t
{
    none = 0,
    a    = 1,
    ptr  = 12,
    txt  = 16,
    aaaa = 28,
    srv  = 33,
    any  = 255,
};

enum class dns_class : uint16_t
{
    none = 0,
    in   = 1,
};

constexpr std::string_view to_string(dns_type t) noexcept
{
    switch (t)
    {
        case dns_type::none: return "none";
        case dns_type::a:    return "A";
        case dns_type::ptr:  return "PTR";
        case dns_type::txt:  return "TXT";
        case dns_type::aaaa: return "AAAA";
        case dns_type::srv:  return "SRV";
        case dns_type::any:  return "ANY";
    }
    return "unknown";
}

} // namespace mdnspp

#endif // HPP_GUARD_MDNSPP_DETAIL_DNS_ENUMS_H

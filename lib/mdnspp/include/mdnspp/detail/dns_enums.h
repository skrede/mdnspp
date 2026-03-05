#ifndef HPP_GUARD_MDNSPP_DNS_ENUMS_H
#define HPP_GUARD_MDNSPP_DNS_ENUMS_H

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

constexpr std::string_view to_string(dns_class c) noexcept
{
    switch (c)
    {
        case dns_class::none: return "none";
        case dns_class::in:   return "IN";
    }
    return "unknown";
}

}

#endif

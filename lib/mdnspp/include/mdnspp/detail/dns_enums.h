#ifndef HPP_GUARD_MDNSPP_DNS_ENUMS_H
#define HPP_GUARD_MDNSPP_DNS_ENUMS_H

#include <cstdint>
#include <string_view>

namespace mdnspp {

enum class dns_type : uint16_t
{
    none = 0u,
    a    = 1u,
    ptr  = 12u,
    txt  = 16u,
    aaaa = 28u,
    srv  = 33u,
    nsec = 47u,
    any  = 255u,
};

enum class dns_class : uint16_t
{
    none = 0u,
    in   = 1u,
};

enum class response_mode : uint8_t
{
    multicast = 0u,
    unicast   = 1u,
};

constexpr std::string_view to_string(dns_type t) noexcept
{
    switch(t)
    {
    case dns_type::none: return "none";
    case dns_type::a: return "A";
    case dns_type::ptr: return "PTR";
    case dns_type::txt: return "TXT";
    case dns_type::aaaa: return "AAAA";
    case dns_type::srv: return "SRV";
    case dns_type::nsec: return "NSEC";
    case dns_type::any: return "ANY";
    }
    return "unknown";
}

constexpr std::string_view to_string(dns_class c) noexcept
{
    switch(c)
    {
    case dns_class::none: return "none";
    case dns_class::in: return "IN";
    }
    return "unknown";
}

constexpr std::string_view to_string(response_mode m) noexcept
{
    switch(m)
    {
    case response_mode::multicast: return "multicast";
    case response_mode::unicast: return "unicast";
    }
    return "unknown";
}

}

#endif

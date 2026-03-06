#ifndef HPP_GUARD_MDNSPP_DNS_H
#define HPP_GUARD_MDNSPP_DNS_H

// dns.h — Public include for DNS vocabulary types.
// Re-exports dns_type, dns_class, and to_string overloads from detail/dns_enums.h,
// and adds stream operators for ergonomic use in logging and diagnostics.

#include "mdnspp/detail/dns_enums.h"

#include <iosfwd>
#include <utility>

namespace mdnspp {

template <typename CharT, typename Traits>
std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &os, dns_type t)
{
    auto sv = to_string(t);
    if(sv != "unknown")
        return os << sv;
    return os << "unknown(" << std::to_underlying(t) << ")";
}

template <typename CharT, typename Traits>
std::basic_ostream<CharT, Traits> &operator<<(std::basic_ostream<CharT, Traits> &os, dns_class c)
{
    auto sv = to_string(c);
    if(sv != "unknown")
        return os << sv;
    return os << "unknown(" << std::to_underlying(c) << ")";
}

}

#endif

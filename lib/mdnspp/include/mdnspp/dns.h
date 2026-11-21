#ifndef HPP_GUARD_MDNSPP_DNS_H
#define HPP_GUARD_MDNSPP_DNS_H

#include "mdnspp/detail/compat.h"
#include "mdnspp/detail/dns_enums.h"

#include <ostream>

namespace mdnspp {

inline std::ostream &operator<<(std::ostream &os, dns_type t)
{
    auto sv = to_string(t);
    if(sv != "unknown")
        return os << sv;
    return os << "unknown(" << detail::to_underlying(t) << ")";
}

inline std::ostream &operator<<(std::ostream &os, dns_class c)
{
    auto sv = to_string(c);
    if(sv != "unknown")
        return os << sv;
    return os << "unknown(" << detail::to_underlying(c) << ")";
}

}

#endif

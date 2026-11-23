#ifndef HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ENUMERATION_H
#define HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ENUMERATION_H

#include "mdnspp/detail/ip_address_ops.h"

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include <optional>
#include <algorithm>

namespace mdnspp::detail {

inline std::optional<address_family> sockaddr_family(const sockaddr &sa) noexcept
{
    if(sa.sa_family == AF_INET)
        return address_family::ipv4;
    if(sa.sa_family == AF_INET6)
        return address_family::ipv6;
    return std::nullopt;
}

// A netmask is read in the family of its address, since a BSD routing netmask need not carry a family of its own.
inline ip_address sockaddr_address(const sockaddr &sa, address_family family) noexcept
{
    if(family == address_family::ipv4)
        return to_ip_address(reinterpret_cast<const sockaddr_in &>(sa).sin_addr);
    return to_ip_address(reinterpret_cast<const sockaddr_in6 &>(sa).sin6_addr);
}

inline void sort_addresses(interface_map &by_name)
{
    for(auto &[_, iface] : by_name)
        std::ranges::sort(iface.addresses, address_before);
}

}

#ifdef _WIN32
#include "mdnspp/detail/interface_enumeration_windows.h"
#else
#include "mdnspp/detail/interface_enumeration_posix.h"
#endif

#endif

#ifndef HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ADDRESSES_H
#define HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ADDRESSES_H

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include <cstddef>
#include <algorithm>

namespace mdnspp::detail {

inline bool is_ipv4_link_local(const ip_address &address) noexcept
{
    return address.family == address_family::ipv4 && address.bytes[0] == std::byte{169} &&
           address.bytes[1] == std::byte{254};
}

inline const ip_network *first_address(const network_interface &nic, address_family family) noexcept
{
    const auto of_family = [family](const ip_network &net) { return net.address.family == family; };
    const auto routable = [&](const ip_network &net) { return of_family(net) && !is_ipv4_link_local(net.address); };
    auto it = std::ranges::find_if(nic.addresses, routable);
    if(it == nic.addresses.end())
        it = std::ranges::find_if(nic.addresses, of_family);
    return it != nic.addresses.end() ? &*it : nullptr;
}

inline bool has_family(const network_interface &nic, address_family family) noexcept
{
    return first_address(nic, family) != nullptr;
}

inline bool contains(const network_interface &nic, const ip_address &address) noexcept
{
    return std::ranges::any_of(nic.addresses, [&address](const ip_network &net) { return net.address == address; });
}

}

#endif

#ifndef HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ADDRESSES_H
#define HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ADDRESSES_H

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include <algorithm>

namespace mdnspp::detail {

inline const ip_network *first_address(const network_interface &nic, address_family family) noexcept
{
    auto it = std::ranges::find_if(nic.addresses,
                                   [family](const ip_network &net) { return net.address.family == family; });
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

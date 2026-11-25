#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_DIFF_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_DIFF_H

#include "mdnspp/detail/interface_addresses.h"

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include <vector>
#include <cstdint>
#include <algorithm>

namespace mdnspp::detail {

enum class nic_change_kind : uint8_t
{
    removed,
    added
};

struct nic_change
{
    nic_change_kind kind;
    network_interface iface;
};

inline bool first_address_changed(const network_interface &before, const network_interface &after,
                                  address_family family) noexcept
{
    const ip_network *old_net = first_address(before, family);
    const ip_network *new_net = first_address(after, family);
    if(old_net == nullptr || new_net == nullptr)
        return old_net != new_net;
    return *old_net != *new_net;
}

// Peers bind and advertise only the first address of each family, so other address churn, such as IPv6 temporary
// addresses rotating, must not restart them.
inline bool nic_changed(const network_interface &before, const network_interface &after)
{
    return after.is_up != before.is_up || first_address_changed(before, after, address_family::ipv4) ||
           first_address_changed(before, after, address_family::ipv6);
}

inline std::vector<network_interface>::const_iterator find_nic(const std::vector<network_interface> &nics,
                                                               uint32_t index)
{
    return std::find_if(nics.begin(), nics.end(),
                        [index](const network_interface &i) { return i.index == index; });
}

// A changed interface (same index, different up state or first address) is reported as a removal followed by an addition.
inline std::vector<nic_change> diff_nics(const std::vector<network_interface> &previous,
                                         const std::vector<network_interface> &next)
{
    std::vector<nic_change> changes;
    for(const auto &old_iface : previous)
    {
        auto new_iface = find_nic(next, old_iface.index);
        if(new_iface == next.end())
            changes.push_back({nic_change_kind::removed, old_iface});
        else if(nic_changed(old_iface, *new_iface))
        {
            changes.push_back({nic_change_kind::removed, old_iface});
            changes.push_back({nic_change_kind::added, *new_iface});
        }
    }
    for(const auto &new_iface : next)
    {
        if(find_nic(previous, new_iface.index) == previous.end())
            changes.push_back({nic_change_kind::added, new_iface});
    }
    return changes;
}

}

#endif

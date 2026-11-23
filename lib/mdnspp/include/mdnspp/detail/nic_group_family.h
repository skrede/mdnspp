#ifndef HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_FAMILY_H
#define HPP_GUARD_MDNSPP_DETAIL_NIC_GROUP_FAMILY_H

#include "mdnspp/detail/ip_address_ops.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include <array>
#include <cstddef>
#include <optional>

namespace mdnspp::detail {

inline constexpr std::array<address_family, 2> address_families{address_family::ipv4, address_family::ipv6};

inline std::size_t family_slot(address_family family) noexcept
{
    return family == address_family::ipv4 ? 0 : 1;
}

template <typename Options>
Options default_family_options(const network_interface &nic, address_family family)
{
    Options opts{};
    opts.interface_index = nic.index;
    opts.multicast_group = family == address_family::ipv4 ? endpoint{"224.0.0.251", 5353} : endpoint{"ff02::fb", 5353};
    return opts;
}

inline bool family_matches(const socket_options &opts, address_family family)
{
    const std::optional<ip_address> group = parse_ip_address(opts.multicast_group.address);
    return group.has_value() && group->family == family;
}

}

#endif

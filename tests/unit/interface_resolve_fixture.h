#ifndef HPP_GUARD_MDNSPP_UNIT_INTERFACE_RESOLVE_FIXTURE_H
#define HPP_GUARD_MDNSPP_UNIT_INTERFACE_RESOLVE_FIXTURE_H

#include "mdnspp/network_interface.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <string_view>

inline mdnspp::network_interface make_nic(uint32_t index, std::string name,
                                          std::string_view ipv4 = {}, std::string_view ipv6 = {},
                                          bool loopback = false, bool up = true)
{
    mdnspp::network_interface nic;
    nic.name = std::move(name);
    if(!ipv4.empty())
        nic.addresses.push_back({*mdnspp::detail::parse_ip_address(ipv4), 24});
    if(!ipv6.empty())
        nic.addresses.push_back({*mdnspp::detail::parse_ip_address(ipv6), 64});
    nic.index = index;
    nic.is_loopback = loopback;
    nic.is_up = up;
    return nic;
}

inline std::vector<mdnspp::network_interface> test_interfaces()
{
    return {
        make_nic(1, "lo", "127.0.0.1", "::1", true),
        make_nic(2, "eth0", "10.0.0.2", "fe80::2"),
        make_nic(3, "eth1", "10.0.1.3"),               // no IPv6
        make_nic(4, "wlan0", {}, "fe80::4"),           // no IPv4
        make_nic(5, "eth2", "10.0.2.5", {}, false, false), // down
    };
}

#endif

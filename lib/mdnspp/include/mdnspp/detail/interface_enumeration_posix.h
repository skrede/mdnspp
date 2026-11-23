#ifndef HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ENUMERATION_POSIX_H
#define HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ENUMERATION_POSIX_H

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/interface_enumeration.h"

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#ifndef _WIN32

#include <net/if.h>
#include <ifaddrs.h>

#include <cerrno>
#include <memory>
#include <string>
#include <cstdint>
#include <optional>
#include <system_error>

namespace mdnspp::detail {

inline void add_ifaddr(interface_map &by_name, const ifaddrs &ifa)
{
    std::string iface_name{ifa.ifa_name};
    auto &iface = by_name[iface_name];
    iface.name = iface_name;
    iface.is_loopback = (ifa.ifa_flags & IFF_LOOPBACK) != 0;
    iface.is_up = (ifa.ifa_flags & IFF_UP) != 0;
    iface.index = static_cast<uint32_t>(if_nametoindex(ifa.ifa_name));

    const std::optional<address_family> family = sockaddr_family(*ifa.ifa_addr);
    if(!family.has_value() || ifa.ifa_netmask == nullptr)
        return;
    ip_address address = sockaddr_address(*ifa.ifa_addr, *family);
#ifdef __APPLE__
    clear_embedded_scope(address);
#endif
    iface.addresses.push_back({address, prefix_from_netmask(sockaddr_address(*ifa.ifa_netmask, *family))});
}

inline void collect_interfaces(interface_map &by_name, std::error_code &ec)
{
    ifaddrs *raw = nullptr;
    if(getifaddrs(&raw) != 0)
    {
        ec = std::error_code{errno, std::system_category()};
        return;
    }

    auto cleanup = [](ifaddrs *p) { freeifaddrs(p); };
    auto addrs = std::unique_ptr<ifaddrs, decltype(cleanup)>{raw, cleanup};

    for(auto *ifa = addrs.get(); ifa != nullptr; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr == nullptr)
            continue;
        add_ifaddr(by_name, *ifa);
    }
    sort_addresses(by_name);
}

}

#endif

#endif

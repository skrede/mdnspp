#ifndef HPP_GUARD_MDNSPP_DETAIL_IPV6_INTERFACE_INDEX_H
#define HPP_GUARD_MDNSPP_DETAIL_IPV6_INTERFACE_INDEX_H

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/ip_address_ops.h"

#include "mdnspp/ip_address.h"

#include <string>
#include <cstddef>
#include <cstdint>

#ifdef _WIN32
#  include <memory>
#  include <iphlpapi.h>
#else
#  include <net/if.h>
#  include <ifaddrs.h>
#endif

namespace mdnspp::detail {

#ifdef _WIN32

inline std::unique_ptr<std::byte[]> load_adapter_addresses()
{
    ULONG buf_size = 15000;
    std::unique_ptr<std::byte[]> buffer;
    ULONG result = ERROR_BUFFER_OVERFLOW;

    for(int32_t attempts = 0; attempts < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempts)
    {
        buffer = std::make_unique<std::byte[]>(buf_size);
        result = GetAdaptersAddresses(AF_UNSPEC, 0, nullptr,
                                      reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get()), &buf_size);
    }
    if(result != NO_ERROR)
        return nullptr;
    return buffer;
}

inline bool unicast_address_matches(const IP_ADAPTER_UNICAST_ADDRESS &ua, const std::string &addr)
{
    const sockaddr *sa = ua.Address.lpSockaddr;
    char buf[INET6_ADDRSTRLEN]{};

    if(sa->sa_family == AF_INET)
    {
        auto *sin = reinterpret_cast<const sockaddr_in *>(sa);
        return inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) && addr == buf;
    }
    if(sa->sa_family == AF_INET6)
    {
        auto *sin6 = reinterpret_cast<const sockaddr_in6 *>(sa);
        return inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) && addr == buf;
    }
    return false;
}

inline uint32_t resolve_ipv6_interface_index(const std::string &addr)
{
    if(addr.empty())
        return 0;
    const auto buffer = load_adapter_addresses();
    if(!buffer)
        return 0;

    for(auto *adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
        adapter != nullptr; adapter = adapter->Next)
        for(auto *ua = adapter->FirstUnicastAddress; ua != nullptr; ua = ua->Next)
            if(unicast_address_matches(*ua, addr))
                return adapter->Ipv6IfIndex ? adapter->Ipv6IfIndex : adapter->IfIndex;
    return 0;
}

#else

inline uint32_t interface_index_of(const ifaddrs *list, const in6_addr &target)
{
    const ip_address wanted = to_ip_address(target);
    for(const ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next)
    {
        if(!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6)
            continue;
        ip_address candidate = to_ip_address(reinterpret_cast<const sockaddr_in6 *>(ifa->ifa_addr)->sin6_addr);
#ifdef __APPLE__
        clear_embedded_scope(candidate);
#endif
        if(candidate == wanted)
            return ::if_nametoindex(ifa->ifa_name);
    }
    return 0;
}

inline uint32_t resolve_ipv6_interface_index(const std::string &addr)
{
    in6_addr target{};
    if(::inet_pton(AF_INET6, addr.c_str(), &target) != 1)
        return 0;
    ifaddrs *addrs{};
    if(::getifaddrs(&addrs) != 0)
        return 0;
    const uint32_t idx = interface_index_of(addrs, target);
    ::freeifaddrs(addrs);
    return idx;
}

#endif

}

#endif

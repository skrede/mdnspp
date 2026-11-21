#ifndef HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ENUMERATION_H
#define HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ENUMERATION_H

#include "mdnspp/network_interface.h"

#ifndef _WIN32
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#else
// ws2tcpip.h must precede iphlpapi.h: netioapi.h declares its user-mode API
// only when ws2ipdef.h has already been included (#ifdef _WS2IPDEF_).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#endif

#include <cerrno>
#include <memory>
#include <string>
#include <cstddef>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

inline void assign_interface_address(network_interface &iface, const sockaddr &sa)
{
    if(sa.sa_family == AF_INET)
    {
        char buf[INET_ADDRSTRLEN]{};
        auto *sin = reinterpret_cast<const sockaddr_in*>(&sa);
        if(inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr)
            iface.ipv4_address = buf;
    }
    else if(sa.sa_family == AF_INET6)
    {
        char buf[INET6_ADDRSTRLEN]{};
        auto *sin6 = reinterpret_cast<const sockaddr_in6*>(&sa);
        if(inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) != nullptr)
            iface.ipv6_address = buf;
    }
}

#ifndef _WIN32

inline void add_ifaddr(interface_map &by_name, const ifaddrs &ifa)
{
    std::string iface_name{ifa.ifa_name};
    auto &iface = by_name[iface_name];
    iface.name = iface_name;
    iface.is_loopback = (ifa.ifa_flags & IFF_LOOPBACK) != 0;
    iface.is_up = (ifa.ifa_flags & IFF_UP) != 0;
    iface.index = static_cast<uint32_t>(if_nametoindex(ifa.ifa_name));
    assign_interface_address(iface, *ifa.ifa_addr);
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
}

#else

inline std::unique_ptr<std::byte[]> fetch_adapter_addresses(std::error_code &ec)
{
    ULONG buf_size = 15000;
    std::unique_ptr<std::byte[]> buffer;
    ULONG result = ERROR_BUFFER_OVERFLOW;

    for(int attempts = 0; attempts < 3 && result == ERROR_BUFFER_OVERFLOW; ++attempts)
    {
        buffer = std::make_unique<std::byte[]>(buf_size);
        result = GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_PREFIX, nullptr,
                                      reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get()), &buf_size);
    }

    if(result != NO_ERROR)
    {
        ec = std::error_code{static_cast<int>(result), std::system_category()};
        return {};
    }
    return buffer;
}

inline std::string adapter_name(PIP_ADAPTER_ADDRESSES adapter)
{
    int name_len = WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
    std::string iface_name(static_cast<std::size_t>(name_len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, iface_name.data(), name_len, nullptr, nullptr);
    return iface_name;
}

inline void add_adapter(interface_map &by_name, PIP_ADAPTER_ADDRESSES adapter)
{
    std::string iface_name = adapter_name(adapter);
    auto &iface = by_name[iface_name];
    iface.name = iface_name;
    iface.index = static_cast<uint32_t>(adapter->IfIndex);
    iface.is_up = (adapter->OperStatus == IfOperStatusUp);
    iface.is_loopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

    for(auto *addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next)
        assign_interface_address(iface, *addr->Address.lpSockaddr);
}

inline void collect_interfaces(interface_map &by_name, std::error_code &ec)
{
    std::unique_ptr<std::byte[]> buffer = fetch_adapter_addresses(ec);
    if(ec)
        return;

    for(auto *adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
        adapter != nullptr; adapter = adapter->Next)
        add_adapter(by_name, adapter);
}

#endif

}

#endif

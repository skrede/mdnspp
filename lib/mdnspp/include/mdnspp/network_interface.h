#ifndef HPP_GUARD_MDNSPP_NETWORK_INTERFACE_H
#define HPP_GUARD_MDNSPP_NETWORK_INTERFACE_H

#ifndef _WIN32
#include <net/if.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#else
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#endif

#include <string>
#include <vector>
#include <memory>
#include <cstring>
#include <algorithm>
#include <system_error>
#include <unordered_map>

namespace mdnspp {

struct network_interface
{
    std::string name;
    std::string ipv4_address;
    std::string ipv6_address;
    unsigned int index{0};
    bool is_loopback{false};
    bool is_up{false};
};

inline std::vector<network_interface> enumerate_interfaces(std::error_code &ec)
{
    ec.clear();
    std::unordered_map<std::string, network_interface> by_name;

#ifndef _WIN32
    ifaddrs *raw = nullptr;
    if(getifaddrs(&raw) != 0)
    {
        ec = std::error_code{errno, std::system_category()};
        return {};
    }

    auto cleanup = [](ifaddrs *p) { freeifaddrs(p); };
    auto addrs = std::unique_ptr<ifaddrs, decltype(cleanup)>{raw, cleanup};

    for(auto *ifa = addrs.get(); ifa != nullptr; ifa = ifa->ifa_next)
    {
        if(ifa->ifa_addr == nullptr)
            continue;

        std::string iface_name{ifa->ifa_name};
        auto &iface = by_name[iface_name];
        iface.name = iface_name;
        iface.is_loopback = (ifa->ifa_flags & IFF_LOOPBACK) != 0;
        iface.is_up = (ifa->ifa_flags & IFF_UP) != 0;
        iface.index = if_nametoindex(ifa->ifa_name);

        if(ifa->ifa_addr->sa_family == AF_INET)
        {
            char buf[INET_ADDRSTRLEN]{};
            auto *sa = reinterpret_cast<const sockaddr_in*>(ifa->ifa_addr);
            if(inet_ntop(AF_INET, &sa->sin_addr, buf, sizeof(buf)) != nullptr)
                iface.ipv4_address = buf;
        }
        else if(ifa->ifa_addr->sa_family == AF_INET6)
        {
            char buf[INET6_ADDRSTRLEN]{};
            auto *sa = reinterpret_cast<const sockaddr_in6*>(ifa->ifa_addr);
            if(inet_ntop(AF_INET6, &sa->sin6_addr, buf, sizeof(buf)) != nullptr)
                iface.ipv6_address = buf;
        }
    }
#else
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

    for(auto *adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
        adapter != nullptr; adapter = adapter->Next)
    {
        int name_len = WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, nullptr, 0, nullptr, nullptr);
        std::string iface_name(static_cast<std::size_t>(name_len - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, iface_name.data(), name_len, nullptr, nullptr);

        auto &iface = by_name[iface_name];
        iface.name = iface_name;
        iface.index = adapter->IfIndex;
        iface.is_up = (adapter->OperStatus == IfOperStatusUp);
        iface.is_loopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

        for(auto *addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next)
        {
            auto *sa = addr->Address.lpSockaddr;
            if(sa->sa_family == AF_INET)
            {
                char buf[INET_ADDRSTRLEN]{};
                auto *sin = reinterpret_cast<const sockaddr_in*>(sa);
                if(inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf)) != nullptr)
                    iface.ipv4_address = buf;
            }
            else if(sa->sa_family == AF_INET6)
            {
                char buf[INET6_ADDRSTRLEN]{};
                auto *sin6 = reinterpret_cast<const sockaddr_in6*>(sa);
                if(inet_ntop(AF_INET6, &sin6->sin6_addr, buf, sizeof(buf)) != nullptr)
                    iface.ipv6_address = buf;
            }
        }
    }
#endif

    std::vector<network_interface> result_vec;
    result_vec.reserve(by_name.size());
    for(auto &[_, iface] : by_name)
        result_vec.push_back(std::move(iface));

    return result_vec;
}

inline std::vector<network_interface> enumerate_interfaces()
{
    std::error_code ec;
    auto result = enumerate_interfaces(ec);
    if(ec)
        throw std::system_error{ec, "enumerate_interfaces"};
    return result;
}

}

#endif

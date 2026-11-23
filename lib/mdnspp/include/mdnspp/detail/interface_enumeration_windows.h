#ifndef HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ENUMERATION_WINDOWS_H
#define HPP_GUARD_MDNSPP_DETAIL_INTERFACE_ENUMERATION_WINDOWS_H

#include "mdnspp/detail/interface_enumeration.h"

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#ifdef _WIN32

// ws2tcpip.h must precede iphlpapi.h: netioapi.h declares its user-mode API
// only when ws2ipdef.h has already been included (#ifdef _WS2IPDEF_).
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <memory>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>

namespace mdnspp::detail {

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
    if(name_len <= 0)
        return {};
    std::string iface_name(static_cast<std::size_t>(name_len - 1), '\0');
    if(WideCharToMultiByte(CP_UTF8, 0, adapter->FriendlyName, -1, iface_name.data(), name_len, nullptr, nullptr) == 0)
        return {};
    return iface_name;
}

inline void add_unicast_address(network_interface &iface, const IP_ADAPTER_UNICAST_ADDRESS &unicast)
{
    const sockaddr &sa = *unicast.Address.lpSockaddr;
    const std::optional<address_family> family = sockaddr_family(sa);
    if(family.has_value())
        iface.addresses.push_back({sockaddr_address(sa, *family), static_cast<uint8_t>(unicast.OnLinkPrefixLength)});
}

inline void add_adapter(interface_map &by_name, PIP_ADAPTER_ADDRESSES adapter)
{
    std::string iface_name = adapter_name(adapter);
    if(iface_name.empty())
        return;
    auto &iface = by_name[iface_name];
    iface.name = iface_name;
    iface.index = static_cast<uint32_t>(adapter->IfIndex);
    iface.is_up = (adapter->OperStatus == IfOperStatusUp);
    iface.is_loopback = (adapter->IfType == IF_TYPE_SOFTWARE_LOOPBACK);

    for(auto *addr = adapter->FirstUnicastAddress; addr != nullptr; addr = addr->Next)
        add_unicast_address(iface, *addr);
}

inline void collect_interfaces(interface_map &by_name, std::error_code &ec)
{
    std::unique_ptr<std::byte[]> buffer = fetch_adapter_addresses(ec);
    if(ec)
        return;

    for(auto *adapter = reinterpret_cast<PIP_ADAPTER_ADDRESSES>(buffer.get());
        adapter != nullptr; adapter = adapter->Next)
        add_adapter(by_name, adapter);
    sort_addresses(by_name);
}

}

#endif

#endif

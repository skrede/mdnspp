#ifndef HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKADDR_H
#define HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKADDR_H

#include "mdnspp/endpoint.h"

#include "mdnspp/detail/native_socket.h"

#include <array>
#include <string>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <charconv>
#include <optional>
#include <string_view>
#include <system_error>

#ifdef _WIN32
#  include <memory>
#  include <iphlpapi.h>
#else
#  include <net/if.h>
#  include <ifaddrs.h>
#endif

namespace mdnspp::detail {

template <std::size_t N>
bool copy_terminated(std::string_view text, std::array<char, N> &buf)
{
    if(text.size() >= N || text.find('\0') != std::string_view::npos)
        return false;
    buf[text.copy(buf.data(), text.size())] = '\0';
    return true;
}

inline bool parse_zone(std::string_view zone, uint32_t &scope)
{
    if(zone.empty())
        return false;
    const char *const end = zone.data() + zone.size();
    const auto [ptr, ec] = std::from_chars(zone.data(), end, scope);
    if(ec == std::errc{} && ptr == end)
        return true;
    std::array<char, IF_NAMESIZE> name{};
    if(!copy_terminated(zone, name))
        return false;
    scope = ::if_nametoindex(name.data());
    return scope != 0;
}

inline bool parse_ipv4(std::string_view text, sockaddr_in &out)
{
    std::array<char, INET_ADDRSTRLEN> addr{};
    return copy_terminated(text, addr) && ::inet_pton(AF_INET, addr.data(), &out.sin_addr) == 1;
}

// RFC 4007 section 11: the zone after '%' is a numeric index or an interface name.
inline bool parse_ipv6(std::string_view text, sockaddr_in6 &out)
{
    const std::size_t percent = text.find('%');
    std::array<char, INET6_ADDRSTRLEN> addr{};
    if(!copy_terminated(text.substr(0, percent), addr) || ::inet_pton(AF_INET6, addr.data(), &out.sin6_addr) != 1)
        return false;
    if(percent == std::string_view::npos)
        return true;
    uint32_t scope{};
    if(!parse_zone(text.substr(percent + 1), scope))
        return false;
    out.sin6_scope_id = scope;
    return true;
}

inline bool is_ipv6(std::string_view addr)
{
    sockaddr_in6 tmp{};
    return parse_ipv6(addr, tmp);
}

struct sockaddr_result
{
    sockaddr_storage ss;
    socklen_t len;
};

template <typename Sockaddr>
sockaddr_result make_sockaddr_result(const Sockaddr &addr)
{
    sockaddr_result r{};
    std::memcpy(&r.ss, &addr, sizeof(addr));
    r.len = sizeof(addr);
    return r;
}

inline std::optional<sockaddr_result> build_sockaddr(const endpoint &dest)
{
    sockaddr_in6 addr6{};
    if(parse_ipv6(dest.address, addr6))
    {
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons(dest.port);
        return make_sockaddr_result(addr6);
    }
    sockaddr_in addr4{};
    if(!parse_ipv4(dest.address, addr4))
        return std::nullopt;
    addr4.sin_family = AF_INET;
    addr4.sin_port = htons(dest.port);
    return make_sockaddr_result(addr4);
}

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
    for(const ifaddrs *ifa = list; ifa; ifa = ifa->ifa_next)
    {
        if(!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET6)
            continue;
        auto &sa6 = *reinterpret_cast<const sockaddr_in6 *>(ifa->ifa_addr);
        if(std::memcmp(&sa6.sin6_addr, &target, sizeof(in6_addr)) == 0)
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

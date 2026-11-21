#ifndef HPP_GUARD_MDNSPP_DETAIL_MDNS_UTIL_H
#define HPP_GUARD_MDNSPP_DETAIL_MDNS_UTIL_H

#include "mdnspp/detail/platform.h"

#ifndef _WIN32
#include <unistd.h>
#endif

#include <array>
#include <cstdio>
#include <string>
#include <cstddef>
#include <cstdint>

namespace mdnspp::detail {

struct ipv6_zero_run
{
    int32_t start;
    int32_t length;
};

inline std::string ipv4_text(const sockaddr_in &in4)
{
    auto *b = reinterpret_cast<const uint8_t*>(&in4.sin_addr);
    char buf[22]; // "255.255.255.255:65535\0"
    if(in4.sin_port != 0)
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
                      b[0], b[1], b[2], b[3], ntohs(in4.sin_port));
    else
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

inline std::array<uint16_t, 8> ipv6_groups(const in6_addr &addr)
{
    auto *b = reinterpret_cast<const uint8_t*>(&addr);
    std::array<uint16_t, 8> groups{};
    for(std::size_t i = 0; i < 8; ++i)
        groups[i] = static_cast<uint16_t>((b[i * 2] << 8) | b[i * 2 + 1]);
    return groups;
}

inline void keep_longer_run(ipv6_zero_run &best, const ipv6_zero_run &current)
{
    if(current.length > best.length)
        best = current;
}

// RFC 5952 section 4.2: "::" replaces the first longest run of two or more zero groups, never a single group.
inline ipv6_zero_run longest_zero_run(const std::array<uint16_t, 8> &groups)
{
    ipv6_zero_run best{-1, 0};
    ipv6_zero_run current{-1, 0};
    for(int32_t i = 0; i < 8; ++i)
    {
        if(groups[static_cast<std::size_t>(i)] == 0)
        {
            if(current.start < 0)
                current.start = i;
            ++current.length;
        }
        else
        {
            keep_longer_run(best, current);
            current = {-1, 0};
        }
    }
    keep_longer_run(best, current);
    if(best.length < 2)
        best.start = -1;
    return best;
}

inline std::string ipv6_host_text(const std::array<uint16_t, 8> &groups, const ipv6_zero_run &run)
{
    std::string host;
    for(int32_t i = 0; i < 8;)
    {
        if(i == run.start)
        {
            host += "::";
            i += run.length;
            continue;
        }
        if(i > 0 && i != run.start + run.length)
            host += ':';
        char g[5];
        std::snprintf(g, sizeof(g), "%x", groups[static_cast<std::size_t>(i)]);
        host += g;
        ++i;
    }
    return host;
}

inline std::string ipv6_text(const sockaddr_in6 &in6)
{
    const std::array<uint16_t, 8> groups = ipv6_groups(in6.sin6_addr);
    std::string host = ipv6_host_text(groups, longest_zero_run(groups));
    if(in6.sin6_port != 0)
        return "[" + host + "]:" + std::to_string(ntohs(in6.sin6_port));
    return host;
}

inline std::string ip_address_to_string(const sockaddr *addr, size_t addrlen)
{
    if(addr->sa_family == AF_INET)
        return ipv4_text(*reinterpret_cast<const sockaddr_in*>(addr));
    if(addr->sa_family == AF_INET6)
        return ipv6_text(*reinterpret_cast<const sockaddr_in6*>(addr));
    (void)addrlen;
    return {};
}

inline std::string ip_address_to_string(const sockaddr_in &addr)
{
    return ip_address_to_string(
        reinterpret_cast<const sockaddr*>(&addr), sizeof(sockaddr_in));
}

inline std::string ip_address_to_string(const sockaddr_in6 &addr)
{
    return ip_address_to_string(
        reinterpret_cast<const sockaddr*>(&addr), sizeof(sockaddr_in6));
}

// ::gethostname needs an initialized Winsock on Windows, and service_info::make() must work without a running
// peer, so Winsock is initialized here once, process-wide, with the WSAStartup(2, 2) call of winsock_guard.
inline std::string os_hostname()
{
#ifdef _WIN32
    static const int wsa_rc = []
    {
        WSADATA data{};
        return ::WSAStartup(MAKEWORD(2, 2), &data);
    }();
    if(wsa_rc != 0)
        return {};
#endif
    char buf[256]{};
    if(::gethostname(buf, sizeof(buf) - 1) != 0)
        return {};
    return std::string{buf};
}

}

#endif

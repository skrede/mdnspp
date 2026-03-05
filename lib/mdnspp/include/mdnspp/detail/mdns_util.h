#ifndef HPP_GUARD_MDNSPP_MDNS_UTIL_H
#define HPP_GUARD_MDNSPP_MDNS_UTIL_H

#include "mdnspp/detail/platform.h"

#include <cstdint>
#include <cstdio>
#include <string>

namespace mdnspp {

inline std::string ip_address_to_string(const sockaddr *addr, size_t addrlen)
{
    if(addr->sa_family == AF_INET)
    {
        auto *in4 = reinterpret_cast<const sockaddr_in*>(addr);
        auto *b = reinterpret_cast<const uint8_t*>(&in4->sin_addr);
        char buf[22]; // "255.255.255.255:65535\0"
        if(in4->sin_port != 0)
            std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u:%u",
                          b[0], b[1], b[2], b[3], ntohs(in4->sin_port));
        else
            std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
        return buf;
    }

    if(addr->sa_family == AF_INET6)
    {
        auto *in6 = reinterpret_cast<const sockaddr_in6*>(addr);
        auto *b = reinterpret_cast<const uint8_t*>(&in6->sin6_addr);

        // Read 8 groups of 16-bit values (network byte order)
        uint16_t groups[8];
        for(int i = 0; i < 8; ++i)
            groups[i] = static_cast<uint16_t>((b[i * 2] << 8) | b[i * 2 + 1]);

        // Find longest run of zero groups for :: compression
        int best_start = -1, best_len = 0;
        int cur_start = -1, cur_len = 0;
        for(int i = 0; i < 8; ++i)
        {
            if(groups[i] == 0)
            {
                if(cur_start < 0) cur_start = i;
                ++cur_len;
            }
            else
            {
                if(cur_len > best_len) { best_start = cur_start; best_len = cur_len; }
                cur_start = -1;
                cur_len = 0;
            }
        }
        if(cur_len > best_len) { best_start = cur_start; best_len = cur_len; }
        if(best_len < 2) best_start = -1; // only compress runs of 2+

        std::string host;
        for(int i = 0; i < 8; )
        {
            if(i == best_start)
            {
                host += "::";
                i += best_len;
                continue;
            }
            if(i > 0 && i != best_start + best_len)
                host += ':';
            char g[5];
            std::snprintf(g, sizeof(g), "%x", groups[i]);
            host += g;
            ++i;
        }

        if(in6->sin6_port != 0)
            return "[" + host + "]:" + std::to_string(ntohs(in6->sin6_port));
        return host;
    }

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

}

#endif

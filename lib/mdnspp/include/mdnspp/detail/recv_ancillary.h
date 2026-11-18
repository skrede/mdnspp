#ifndef HPP_GUARD_MDNSPP_DETAIL_RECV_ANCILLARY_H
#define HPP_GUARD_MDNSPP_DETAIL_RECV_ANCILLARY_H

#include "mdnspp/detail/native_socket.h"

#include "mdnspp/endpoint.h"

#include <cstdint>
#include <cstring>
#include <optional>
#include <algorithm>

namespace mdnspp::detail {

struct ancillary_data
{
    std::optional<uint8_t> ttl;
    uint32_t ifindex;
};

#ifdef _WIN32
using pktinfo4_t = IN_PKTINFO;
using pktinfo6_t = IN6_PKTINFO;
#else
#  ifdef IP_PKTINFO
using pktinfo4_t = in_pktinfo;
#  endif
using pktinfo6_t = in6_pktinfo;
#endif

inline endpoint endpoint_from_sockaddr(const sockaddr_storage &addr)
{
    char text[INET6_ADDRSTRLEN]{};
    if(addr.ss_family == AF_INET6)
    {
        const auto &sa6 = reinterpret_cast<const sockaddr_in6 &>(addr);
        ::inet_ntop(AF_INET6, &sa6.sin6_addr, text, sizeof(text));
        return {text, ntohs(sa6.sin6_port)};
    }
    const auto &sa4 = reinterpret_cast<const sockaddr_in &>(addr);
    ::inet_ntop(AF_INET, &sa4.sin_addr, text, sizeof(text));
    return {text, ntohs(sa4.sin_port)};
}

inline void read_ttl_message(int level, int type, const void *data, ancillary_data &out)
{
    bool is_ttl = level == IPPROTO_IP && type == IP_TTL;
#ifdef IPV6_HOPLIMIT
    is_ttl = is_ttl || (level == IPPROTO_IPV6 && type == IPV6_HOPLIMIT);
#endif
    if(!is_ttl)
        return;
    int value{};
    std::memcpy(&value, data, sizeof(value));
    out.ttl = static_cast<uint8_t>(value);
}

inline void read_ifindex_v4_message(int level, int type, const void *data,
                                    [[maybe_unused]] std::size_t data_len, ancillary_data &out)
{
#if defined(IP_PKTINFO)
    if(level == IPPROTO_IP && type == IP_PKTINFO)
    {
        pktinfo4_t info{};
        std::memcpy(&info, data, sizeof(info));
        out.ifindex = static_cast<uint32_t>(info.ipi_ifindex);
    }
#elif defined(__APPLE__) && defined(IP_RECVIF)
    if(level == IPPROTO_IP && type == IP_RECVIF)
    {
        sockaddr_dl sdl{};
        std::memcpy(&sdl, data, (std::min)(sizeof(sdl), data_len));
        out.ifindex = static_cast<uint32_t>(sdl.sdl_index);
    }
#endif
}

inline void read_ifindex_v6_message(int level, int type, const void *data, ancillary_data &out)
{
#ifdef IPV6_PKTINFO
    if(level == IPPROTO_IPV6 && type == IPV6_PKTINFO)
    {
        pktinfo6_t info{};
        std::memcpy(&info, data, sizeof(info));
        out.ifindex = static_cast<uint32_t>(info.ipi6_ifindex);
    }
#endif
}

inline void read_control_message(int level, int type, const void *data,
                                 std::size_t data_len, ancillary_data &out)
{
    read_ttl_message(level, type, data, out);
    read_ifindex_v4_message(level, type, data, data_len, out);
    read_ifindex_v6_message(level, type, data, out);
}

#ifdef _WIN32
inline ancillary_data parse_ancillary(WSAMSG &msg)
{
    ancillary_data out{};
    for(WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(&msg); cmsg; cmsg = WSA_CMSG_NXTHDR(&msg, cmsg))
    {
        const std::size_t data_len = static_cast<std::size_t>(cmsg->cmsg_len) - sizeof(WSACMSGHDR);
        read_control_message(cmsg->cmsg_level, cmsg->cmsg_type, WSA_CMSG_DATA(cmsg), data_len, out);
    }
    return out;
}
#else
inline ancillary_data parse_ancillary(msghdr &msg)
{
    ancillary_data out{};
    for(cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
        const std::size_t data_len = static_cast<std::size_t>(cmsg->cmsg_len) - sizeof(cmsghdr);
        read_control_message(cmsg->cmsg_level, cmsg->cmsg_type, CMSG_DATA(cmsg), data_len, out);
    }
    return out;
}
#endif

}

#endif

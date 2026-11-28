#ifndef HPP_GUARD_MDNSPP_DETAIL_RECV_ANCILLARY_H
#define HPP_GUARD_MDNSPP_DETAIL_RECV_ANCILLARY_H

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/ip_address_ops.h"

#include "mdnspp/ip_address.h"

#include <span>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <algorithm>

namespace mdnspp::detail {

struct ancillary_data
{
    std::optional<uint8_t> ttl;
    uint32_t ifindex;
    std::optional<ip_address> destination;
};

struct control_payload
{
    int32_t level;
    int32_t type;
    std::span<const std::byte> bytes;
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

template <typename T>
bool read_payload(std::span<const std::byte> bytes, T &out)
{
    if(bytes.size() < sizeof(T))
        return false;
    std::memcpy(&out, bytes.data(), sizeof(T));
    return true;
}

inline std::span<const std::byte> bounded_payload(const void *header, const void *data, std::size_t declared_len,
                                                  const std::byte *buffer_end)
{
    const auto *start = static_cast<const std::byte *>(header);
    const auto *first = static_cast<const std::byte *>(data);
    const std::size_t length = (std::min)(declared_len, static_cast<std::size_t>(buffer_end - start));
    const auto offset = static_cast<std::size_t>(first - start);
    if(length < offset)
        return {};
    return {first, length - offset};
}

inline bool is_int_ttl(const control_payload &msg)
{
    bool is_ttl = msg.level == IPPROTO_IP && msg.type == IP_TTL;
#if defined(_WIN32) && defined(IP_RECVTTL)
    // Windows does not document the control message type that carries the IPv4 TTL, so both candidates are read.
    is_ttl = is_ttl || (msg.level == IPPROTO_IP && msg.type == IP_RECVTTL);
#endif
#ifdef IPV6_HOPLIMIT
    is_ttl = is_ttl || (msg.level == IPPROTO_IPV6 && msg.type == IPV6_HOPLIMIT);
#endif
    return is_ttl;
}

inline void read_ttl_message(const control_payload &msg, ancillary_data &out)
{
#if defined(__APPLE__) && defined(IP_RECVTTL)
    // Darwin reports the IPv4 TTL as an IP_RECVTTL message carrying a single u_char.
    uint8_t byte_ttl{};
    if(msg.level == IPPROTO_IP && msg.type == IP_RECVTTL && read_payload(msg.bytes, byte_ttl))
        out.ttl = byte_ttl;
#endif
    int32_t int_ttl{};
    if(is_int_ttl(msg) && read_payload(msg.bytes, int_ttl))
        out.ttl = static_cast<uint8_t>(int_ttl);
}

// ipi_addr is the IP header destination; ipi_spec_dst is the preferred reply source on Linux and zero on xnu.
inline void read_pktinfo_v4_message(const control_payload &msg, ancillary_data &out)
{
#ifdef IP_PKTINFO
    pktinfo4_t info{};
    if(msg.level != IPPROTO_IP || msg.type != IP_PKTINFO || !read_payload(msg.bytes, info))
        return;
    out.ifindex = static_cast<uint32_t>(info.ipi_ifindex);
    out.destination = to_ip_address(info.ipi_addr);
#endif
}

#ifdef IPV6_PKTINFO
inline void read_pktinfo_v6_message(const control_payload &msg, ancillary_data &out)
{
    pktinfo6_t info{};
    if(msg.level != IPPROTO_IPV6 || msg.type != IPV6_PKTINFO || !read_payload(msg.bytes, info))
        return;
    out.ifindex = static_cast<uint32_t>(info.ipi6_ifindex);
    out.destination = to_ip_address(info.ipi6_addr);
}
#endif

inline void read_control_message(const control_payload &msg, ancillary_data &out)
{
    read_ttl_message(msg, out);
    read_pktinfo_v4_message(msg, out);
#ifdef IPV6_PKTINFO
    read_pktinfo_v6_message(msg, out);
#endif
}

#ifdef _WIN32
inline ancillary_data parse_ancillary(WSAMSG &msg)
{
    ancillary_data out{};
    if(msg.dwFlags & MSG_CTRUNC)
        return out;
    const std::byte *end = reinterpret_cast<const std::byte *>(msg.Control.buf) + msg.Control.len;
    for(WSACMSGHDR *cmsg = WSA_CMSG_FIRSTHDR(&msg); cmsg; cmsg = WSA_CMSG_NXTHDR(&msg, cmsg))
    {
        const auto declared = static_cast<std::size_t>(cmsg->cmsg_len);
        const std::span<const std::byte> bytes = bounded_payload(cmsg, WSA_CMSG_DATA(cmsg), declared, end);
        read_control_message(control_payload{cmsg->cmsg_level, cmsg->cmsg_type, bytes}, out);
    }
    return out;
}
#else
inline ancillary_data parse_ancillary(msghdr &msg)
{
    ancillary_data out{};
    if(msg.msg_flags & MSG_CTRUNC)
        return out;
    const std::byte *end = static_cast<const std::byte *>(msg.msg_control) + msg.msg_controllen;
    for(cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg))
    {
        const auto declared = static_cast<std::size_t>(cmsg->cmsg_len);
        const std::span<const std::byte> bytes = bounded_payload(cmsg, CMSG_DATA(cmsg), declared, end);
        read_control_message(control_payload{cmsg->cmsg_level, cmsg->cmsg_type, bytes}, out);
    }
    return out;
}
#endif

}

#endif

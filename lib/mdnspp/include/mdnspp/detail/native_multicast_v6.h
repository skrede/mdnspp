#ifndef HPP_GUARD_MDNSPP_DETAIL_NATIVE_MULTICAST_V6_H
#define HPP_GUARD_MDNSPP_DETAIL_NATIVE_MULTICAST_V6_H

#include "mdnspp/socket_options.h"

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/native_socket_opts.h"
#include "mdnspp/detail/ipv6_interface_index.h"

#include <string>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

inline bool bind_any_v6(native_socket_t fd, uint16_t port, std::error_code &ec)
{
    sockaddr_in6 addr{};
    addr.sin6_family = AF_INET6;
    addr.sin6_addr = in6addr_any;
    addr.sin6_port = htons(port);
    return bind_socket(fd, reinterpret_cast<const sockaddr *>(&addr), static_cast<socklen_t>(sizeof(addr)), ec);
}

inline bool join_v6_group(native_socket_t fd, const socket_options &opts, uint32_t iface_idx, std::error_code &ec)
{
    ipv6_mreq mreq{};
    ::inet_pton(AF_INET6, opts.multicast_group.address.c_str(), &mreq.ipv6mr_multiaddr);
    mreq.ipv6mr_interface = iface_idx;
    return set_option(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, mreq, ec);
}

inline bool set_v6_multicast_options(native_socket_t fd, const socket_options &opts, std::error_code &ec)
{
    const int32_t hops = static_cast<int32_t>(opts.multicast_ttl.value_or(255));
    const int32_t loop = (opts.multicast_loopback == loopback_mode::enabled) ? 1 : 0;
    return set_option(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, hops, ec)
        && set_option(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, loop, ec);
}

inline void enable_v6_receive_info(native_socket_t fd)
{
#ifdef IPV6_RECVHOPLIMIT
    set_flag_best_effort(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT);
#endif
#ifdef IPV6_RECVPKTINFO
    set_flag_best_effort(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO);
#endif
}

inline void configure_ipv6(native_socket_t fd, const socket_options &opts, const std::string &iface_address,
                           std::error_code &ec)
{
    const uint32_t iface_idx = resolve_ipv6_interface_index(iface_address);
    if(!iface_address.empty() && iface_idx == 0)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return;
    }
    if(!bind_any_v6(fd, opts.multicast_group.port, ec))
        return;
    if(!iface_address.empty() && !set_option(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, iface_idx, ec))
        return;
    if(!join_v6_group(fd, opts, iface_idx, ec) || !set_v6_multicast_options(fd, opts, ec))
        return;
    enable_v6_receive_info(fd);
}

}

#endif

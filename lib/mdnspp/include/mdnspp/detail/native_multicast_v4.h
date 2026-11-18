#ifndef HPP_GUARD_MDNSPP_DETAIL_NATIVE_MULTICAST_V4_H
#define HPP_GUARD_MDNSPP_DETAIL_NATIVE_MULTICAST_V4_H

#include "mdnspp/socket_options.h"

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/native_socket_opts.h"

#include <string>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

inline bool bind_any_v4(native_socket_t fd, uint16_t port, std::error_code &ec)
{
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    return bind_socket(fd, reinterpret_cast<const sockaddr *>(&addr), static_cast<socklen_t>(sizeof(addr)), ec);
}

inline bool parse_v4_interface(const std::string &iface_address, in_addr &out, std::error_code &ec)
{
    if(iface_address.empty())
        out.s_addr = htonl(INADDR_ANY);
    else if(::inet_pton(AF_INET, iface_address.c_str(), &out) != 1)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return false;
    }
    return true;
}

inline bool join_v4_group(native_socket_t fd, const socket_options &opts, const in_addr &iface_addr,
                          std::error_code &ec)
{
    ip_mreq mreq{};
    ::inet_pton(AF_INET, opts.multicast_group.address.c_str(), &mreq.imr_multiaddr);
    mreq.imr_interface = iface_addr;
    return set_option(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, mreq, ec);
}

inline bool set_v4_multicast_options(native_socket_t fd, const socket_options &opts, std::error_code &ec)
{
    const int32_t ttl = static_cast<int32_t>(opts.multicast_ttl.value_or(255));
    const int32_t loop = (opts.multicast_loopback == loopback_mode::enabled) ? 1 : 0;
    return set_option(fd, IPPROTO_IP, IP_MULTICAST_TTL, ttl, ec)
        && set_option(fd, IPPROTO_IP, IP_MULTICAST_LOOP, loop, ec);
}

inline void enable_v4_receive_info(native_socket_t fd)
{
#ifdef IP_RECVTTL
    set_flag_best_effort(fd, IPPROTO_IP, IP_RECVTTL);
#endif
#if defined(IP_PKTINFO)
    set_flag_best_effort(fd, IPPROTO_IP, IP_PKTINFO);
#elif defined(__APPLE__) && defined(IP_RECVIF)
    set_flag_best_effort(fd, IPPROTO_IP, IP_RECVIF);
#endif
}

inline void configure_ipv4(native_socket_t fd, const socket_options &opts, const std::string &iface_address,
                           std::error_code &ec)
{
    in_addr iface_addr{};
    if(!bind_any_v4(fd, opts.multicast_group.port, ec) || !parse_v4_interface(iface_address, iface_addr, ec))
        return;
    if(!iface_address.empty() && !set_option(fd, IPPROTO_IP, IP_MULTICAST_IF, iface_addr, ec))
        return;
    if(!join_v4_group(fd, opts, iface_addr, ec) || !set_v4_multicast_options(fd, opts, ec))
        return;
    enable_v4_receive_info(fd);
}

}

#endif

#ifndef HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKET_SETUP_H
#define HPP_GUARD_MDNSPP_DETAIL_NATIVE_SOCKET_SETUP_H

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/native_sockaddr.h"
#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/native_socket_opts.h"
#include "mdnspp/detail/validate_multicast.h"
#include "mdnspp/detail/native_multicast_v4.h"
#include "mdnspp/detail/native_multicast_v6.h"

#include "mdnspp/socket_options.h"

#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

#ifdef _WIN32
inline LPFN_WSARECVMSG load_wsarecvmsg(native_socket_t fd)
{
    GUID guid = WSAID_WSARECVMSG;
    LPFN_WSARECVMSG fn = nullptr;
    DWORD bytes_returned = 0;
    if(::WSAIoctl(fd, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
                  &fn, sizeof(fn), &bytes_returned, nullptr, nullptr) == SOCKET_ERROR)
        return nullptr;
    return fn;
}
#endif

inline void prepare_socket(native_socket_t fd, const socket_options &opts, bool v6,
                           const resolved_interface &iface, std::error_code &ec)
{
    if(!set_option(fd, SOL_SOCKET, SO_REUSEADDR, int32_t{1}, ec))
        return;
#if defined(SO_REUSEPORT)
    set_flag_best_effort(fd, SOL_SOCKET, SO_REUSEPORT);
#endif
    if(!set_nonblocking(fd, ec))
        return;
    if(v6)
        configure_ipv6(fd, opts, iface, ec);
    else
        configure_ipv4(fd, opts, iface, ec);
}

inline native_socket_t open_and_configure(const socket_options &opts, std::error_code &ec)
{
    ec.clear();
    validate_multicast_address(opts.multicast_group.address, ec);
    if(ec)
        return invalid_socket;

    const bool v6 = is_ipv6(opts.multicast_group.address);
    // precedence index > name > address; an unknown index or name fails with invalid_argument
    const resolved_interface iface =
        resolve_socket_interface(opts, v6 ? address_family::ipv6 : address_family::ipv4, ec);
    if(ec)
        return invalid_socket;

    const native_socket_t fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(fd == invalid_socket)
    {
        ec = last_socket_error();
        return invalid_socket;
    }
    prepare_socket(fd, opts, v6, iface, ec);
    if(!ec)
        return fd;
    close_socket(fd);
    return invalid_socket;
}

inline native_socket_t open_and_configure(const socket_options &opts)
{
    std::error_code ec;
    const native_socket_t fd = open_and_configure(opts, ec);
    if(ec)
        throw std::system_error(ec, "default_socket::open_and_configure");
    return fd;
}

}

#endif

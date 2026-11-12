#ifndef HPP_GUARD_MDNSPP_ASIO_DETAIL_ASIO_SOCKET_SETUP_H
#define HPP_GUARD_MDNSPP_ASIO_DETAIL_ASIO_SOCKET_SETUP_H

#include "mdnspp/socket_options.h"

#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/native_multicast_v4.h"
#include "mdnspp/detail/native_multicast_v6.h"
#include "mdnspp/detail/validate_multicast.h"

#include <asio.hpp>

#include <string>
#include <cstdint>
#include <system_error>

namespace mdnspp::detail {

inline void enable_receive_info(asio::ip::udp::socket &socket, bool v6)
{
    if(v6)
        enable_v6_receive_info(socket.native_handle());
    else
        enable_v4_receive_info(socket.native_handle());
}

// Set alongside asio's reuse_address so co-located same-port multicast sockets
// each receive the fan-out on every kernel; must precede bind.
inline void apply_reuse_port(asio::ip::udp::socket &socket)
{
#if defined(SO_REUSEPORT)
    set_flag_best_effort(socket.native_handle(), SOL_SOCKET, SO_REUSEPORT);
#endif
}

inline void open_socket(asio::ip::udp::socket &socket, bool v6, std::error_code &ec)
{
    socket.open(v6 ? asio::ip::udp::v6() : asio::ip::udp::v4(), ec);
    if(ec)
        return;
    socket.non_blocking(true, ec);
    if(ec)
        return;
    enable_receive_info(socket, v6);
    socket.set_option(asio::ip::udp::socket::reuse_address(true), ec);
    if(ec)
        return;
    apply_reuse_port(socket);
}

inline void bind_any(asio::ip::udp::socket &socket, bool v6, uint16_t port, std::error_code &ec)
{
    const asio::ip::address any = v6 ? asio::ip::address{asio::ip::address_v6::any()}
                                     : asio::ip::address{asio::ip::address_v4::any()};
    socket.bind(asio::ip::udp::endpoint(any, port), ec);
}

inline void join_v6(asio::ip::udp::socket &socket, const asio::ip::address &group,
                    const std::string &iface_address, std::error_code &ec)
{
    if(!iface_address.empty())
    {
        const asio::ip::address_v6 iface = asio::ip::make_address_v6(iface_address, ec);
        if(ec)
            return;
        socket.set_option(asio::ip::multicast::outbound_interface(static_cast<unsigned int>(iface.scope_id())), ec);
        if(ec)
            return;
    }
    socket.set_option(asio::ip::multicast::join_group(group), ec);
}

inline void join_v4(asio::ip::udp::socket &socket, const asio::ip::address &group,
                    const std::string &iface_address, std::error_code &ec)
{
    if(iface_address.empty())
    {
        socket.set_option(asio::ip::multicast::join_group(group), ec);
        return;
    }
    const asio::ip::address_v4 iface = asio::ip::make_address_v4(iface_address, ec);
    if(ec)
        return;
    socket.set_option(asio::ip::multicast::outbound_interface(iface), ec);
    if(ec)
        return;
    socket.set_option(asio::ip::multicast::join_group(group.to_v4(), iface), ec);
}

inline void set_multicast_options(asio::ip::udp::socket &socket, const socket_options &opts, std::error_code &ec)
{
    socket.set_option(asio::ip::multicast::hops(opts.multicast_ttl.value_or(255)), ec);
    if(ec)
        return;
    socket.set_option(asio::ip::multicast::enable_loopback(opts.multicast_loopback == loopback_mode::enabled), ec);
}

inline void configure(asio::ip::udp::socket &socket, const socket_options &opts, std::error_code &ec)
{
    validate_multicast_address(opts.multicast_group.address, ec);
    if(ec)
        return;
    const asio::ip::address group = asio::ip::make_address(opts.multicast_group.address, ec);
    if(ec)
        return;
    const bool v6 = group.is_v6();
    // precedence index > name > address; an unknown index or name fails with invalid_argument
    const std::string iface_address = resolve_socket_interface_address(opts, v6, ec);
    if(ec)
        return;
    open_socket(socket, v6, ec);
    if(!ec)
        bind_any(socket, v6, opts.multicast_group.port, ec);
    if(!ec && v6)
        join_v6(socket, group, iface_address, ec);
    else if(!ec)
        join_v4(socket, group, iface_address, ec);
    if(!ec)
        set_multicast_options(socket, opts, ec);
}

}

#endif

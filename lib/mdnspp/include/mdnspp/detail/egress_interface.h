#ifndef HPP_GUARD_MDNSPP_DETAIL_EGRESS_INTERFACE_H
#define HPP_GUARD_MDNSPP_DETAIL_EGRESS_INTERFACE_H

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/native_sockaddr.h"
#include "mdnspp/detail/native_socket_opts.h"
#include "mdnspp/detail/interface_addresses.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <algorithm>
#include <system_error>

namespace mdnspp::detail {

inline std::optional<ip_address> connected_source(native_socket_t fd, const endpoint &group, std::error_code &ec)
{
    const std::optional<sockaddr_result> to = build_sockaddr(group);
    if(!to.has_value() || to->ss.ss_family != AF_INET)
    {
        ec = std::make_error_code(std::errc::invalid_argument);
        return std::nullopt;
    }
    if(::connect(fd, reinterpret_cast<const sockaddr *>(&to->ss), to->len) != 0)
    {
        ec = last_socket_error();
        return std::nullopt;
    }
    sockaddr_in local{};
    socklen_t length = static_cast<socklen_t>(sizeof(local));
    if(::getsockname(fd, reinterpret_cast<sockaddr *>(&local), &length) != 0)
    {
        ec = last_socket_error();
        return std::nullopt;
    }
    return to_ip_address(local.sin_addr);
}

// Connecting a UDP socket sends nothing: the kernel runs its route lookup for the destination and binds the source
// address of the interface it would send on. An IPv6 link-local group cannot be connected without a scope, so an
// IPv6 group is looked up through the IPv4 mDNS group on the same port.
inline std::optional<ip_address> egress_source_address(const endpoint &group, std::error_code &ec)
{
    ec.clear();
    const winsock_guard winsock{ec};
    if(ec)
        return std::nullopt;
    const endpoint probe = is_ipv6(group.address) ? endpoint{std::string{default_ipv4_group}, group.port} : group;
    const native_socket_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(fd == invalid_socket)
    {
        ec = last_socket_error();
        return std::nullopt;
    }
    const std::optional<ip_address> source = connected_source(fd, probe, ec);
    close_socket(fd);
    return source;
}

inline const network_interface *
egress_interface(const std::vector<network_interface> &interfaces, const ip_address &source) noexcept
{
    const auto carries = [&](const network_interface &nic) { return contains(nic, source); };
    const auto it = std::ranges::find_if(interfaces, carries);
    return it != interfaces.end() ? &*it : nullptr;
}

inline const network_interface *
find_egress_interface(const std::vector<network_interface> &interfaces, const endpoint &group, std::error_code &ec)
{
    const std::optional<ip_address> source = egress_source_address(group, ec);
    return source.has_value() ? egress_interface(interfaces, *source) : nullptr;
}

// A failed lookup is not an error: the socket stays unpinned and the kernel picks the interface per packet.
inline uint32_t egress_ipv6_index(const endpoint &group)
{
    std::error_code ec;
    const std::vector<network_interface> interfaces = enumerate_interfaces(ec);
    const network_interface *nic = ec ? nullptr : find_egress_interface(interfaces, group, ec);
    return nic != nullptr && has_family(*nic, address_family::ipv6) ? nic->index : 0;
}

}

#endif

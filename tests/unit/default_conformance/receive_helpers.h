#ifndef HPP_GUARD_MDNSPP_DEFAULT_CONFORMANCE_RECEIVE_HELPERS_H
#define HPP_GUARD_MDNSPP_DEFAULT_CONFORMANCE_RECEIVE_HELPERS_H

#include "support/skip_or_fail.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/interface_addresses.h"

#include "mdnspp/default/default_timer.h"
#include "mdnspp/default/default_socket.h"
#include "mdnspp/default/default_context.h"

#include <span>
#include <array>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>

inline constexpr std::chrono::milliseconds receive_deadline{2000};
inline const std::array<std::byte, 4> probe_payload{};

inline uint16_t bound_port(mdnspp::detail::native_socket_t fd)
{
    sockaddr_storage addr{};
    socklen_t len = static_cast<socklen_t>(sizeof(addr));
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
    if(addr.ss_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6 &>(addr).sin6_port);
    return ntohs(reinterpret_cast<const sockaddr_in &>(addr).sin_port);
}

inline int32_t ttl_of(const std::optional<mdnspp::recv_metadata> &meta)
{
    return meta && meta->ttl ? int32_t{*meta->ttl} : -1;
}

inline mdnspp::socket_options loopback_options(const char *group, const char *loopback)
{
    mdnspp::socket_options opts;
    opts.multicast_group = mdnspp::endpoint{group, 0};
    // Without it the join takes the default multicast route, and Darwin rejects an IPv6 link-local group join with
    // interface index 0 when it has no IPv6 route to the group.
    opts.interface_address = loopback;
    return opts;
}

inline mdnspp::socket_options interface_options(const char *group, uint32_t index)
{
    mdnspp::socket_options opts;
    opts.multicast_group = mdnspp::endpoint{group, 0};
    opts.interface_index = index;
    return opts;
}

inline uint32_t loopback_index()
{
    for(const mdnspp::network_interface &nic : mdnspp::enumerate_interfaces())
        if(nic.is_loopback)
            return nic.index;
    mdnspp::test_support::skip_or_fail("no loopback interface");
    return 0;
}

inline uint32_t multicast_interface_index(bool ipv6)
{
    const auto family = ipv6 ? mdnspp::address_family::ipv6 : mdnspp::address_family::ipv4;
    uint32_t index = 0;
    for(const mdnspp::network_interface &nic : mdnspp::enumerate_interfaces())
    {
        const bool candidate = nic.is_up && !nic.is_loopback && mdnspp::detail::has_family(nic, family);
        if(candidate && (index == 0 || nic.index < index))
            index = nic.index;
    }
    if(index == 0)
        mdnspp::test_support::skip_or_fail("no up, non-loopback interface with an address of the family");
    return index;
}

template <typename Send>
std::optional<mdnspp::recv_metadata> receive_with(const mdnspp::socket_options &opts, Send send)
{
    mdnspp::default_context ctx;
    std::error_code ec;
    std::optional<mdnspp::recv_metadata> received;
    bool expired = false;
    mdnspp::default_socket socket(ctx, opts, ec);
    if(ec)
        mdnspp::test_support::skip_or_fail("default_socket construction failed: " + ec.message());
    socket.async_receive([&](std::error_code result, const mdnspp::recv_metadata &meta, std::span<std::byte>)
    {
        if(!result)
            received = meta;
    });
    mdnspp::default_timer deadline(ctx);
    deadline.expires_after(receive_deadline);
    deadline.async_wait([&](std::error_code) { expired = true; });
    send(socket, bound_port(socket.native_handle()));
    while(!received && !expired)
        ctx.poll_one();
    return received;
}

inline std::optional<mdnspp::recv_metadata> receive_from_self(const mdnspp::socket_options &opts, const char *to)
{
    return receive_with(opts, [to](mdnspp::default_socket &socket, uint16_t port)
    {
        socket.send(mdnspp::endpoint{to, port}, probe_payload);
    });
}

#endif

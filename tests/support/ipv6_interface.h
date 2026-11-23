#ifndef HPP_GUARD_MDNSPP_SUPPORT_IPV6_INTERFACE_H
#define HPP_GUARD_MDNSPP_SUPPORT_IPV6_INTERFACE_H

#include "support/skip_or_fail.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/interface_addresses.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>
#include <utility>

namespace mdnspp::test_support {

inline socket_options ipv6_group_options(std::string iface_address = {})
{
    return socket_options{
        .interface_address = std::move(iface_address),
        .multicast_group = endpoint{"ff02::fb", 0},
    };
}

inline uint32_t ipv6_multicast_interface(detail::native_socket_t fd)
{
#ifdef _WIN32
    DWORD index = 0;
    socklen_t len = static_cast<socklen_t>(sizeof(index));
    REQUIRE(::getsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, reinterpret_cast<char *>(&index), &len) == 0);
#else
    uint32_t index = 0;
    socklen_t len = sizeof(index);
    REQUIRE(::getsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, &len) == 0);
#endif
    return static_cast<uint32_t>(index);
}

inline network_interface loopback_ipv6_interface()
{
    const ip_address loopback = *detail::parse_ip_address("::1");
    for(network_interface &nic : enumerate_interfaces())
        if(detail::contains(nic, loopback))
            return std::move(nic);
    skip_or_fail("no interface carries ::1");
    return {};
}

}

#endif

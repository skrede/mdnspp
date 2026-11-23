#ifndef HPP_GUARD_MDNSPP_GATE_METADATA_H
#define HPP_GUARD_MDNSPP_GATE_METADATA_H

#include "support/skip_or_fail.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/interface_addresses.h"

#include "mdnspp/testing/mock_socket.h"

#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>
#include <system_error>

inline mdnspp::ip_address address_of(std::string_view text)
{
    return *mdnspp::detail::parse_ip_address(text);
}

inline uint32_t loopback_index()
{
    std::error_code ec;
    const mdnspp::ip_address loopback = address_of("127.0.0.1");
    for(const mdnspp::network_interface &nic : mdnspp::enumerate_interfaces(ec))
    {
        if(mdnspp::detail::contains(nic, loopback))
            return nic.index;
    }
    mdnspp::test_support::skip_or_fail("no interface carries 127.0.0.1");
    return 0;
}

inline mdnspp::recv_metadata arriving(const mdnspp::testing::mock_socket &socket, mdnspp::endpoint sender,
                                      std::optional<mdnspp::ip_address> destination, uint32_t recv_ifindex)
{
    mdnspp::recv_metadata meta = socket.default_metadata();
    meta.sender = std::move(sender);
    meta.destination = destination;
    meta.recv_ifindex = recv_ifindex;
    return meta;
}

inline mdnspp::recv_metadata sent_from_port(const mdnspp::testing::mock_socket &socket, uint16_t port)
{
    mdnspp::recv_metadata meta = socket.default_metadata();
    meta.sender = mdnspp::endpoint{"192.0.2.10", port};
    return meta;
}

#endif

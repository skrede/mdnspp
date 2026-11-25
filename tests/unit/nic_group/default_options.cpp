#include "mdnspp/ip_address.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/nic_group_family.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

using mdnspp::address_family;
using mdnspp::detail::default_family_options;

namespace {

mdnspp::network_interface nic_with_index(uint32_t index)
{
    mdnspp::network_interface nic;
    nic.name = "nic";
    nic.index = index;
    return nic;
}

}

TEST_CASE("the default IPv4 options pin the NIC and join the IPv4 mDNS group", "[nic_group][family]")
{
    const mdnspp::socket_options opts =
        default_family_options<mdnspp::socket_options>(nic_with_index(7), address_family::ipv4);

    REQUIRE(opts.interface_index.has_value());
    CHECK(*opts.interface_index == 7);
    CHECK(opts.multicast_group.address == "224.0.0.251");
    CHECK(opts.multicast_group.port == 5353);
}

TEST_CASE("the default IPv6 options pin the NIC and join the IPv6 mDNS group", "[nic_group][family]")
{
    const mdnspp::socket_options opts =
        default_family_options<mdnspp::socket_options>(nic_with_index(42), address_family::ipv6);

    REQUIRE(opts.interface_index.has_value());
    CHECK(*opts.interface_index == 42);
    CHECK(opts.multicast_group.address == "ff02::fb");
    CHECK(opts.multicast_group.port == 5353);
}

TEST_CASE("the default options of one NIC share its interface and differ in the multicast group between families",
          "[nic_group][family]")
{
    const mdnspp::network_interface nic = nic_with_index(3);
    const mdnspp::socket_options v4 = default_family_options<mdnspp::socket_options>(nic, address_family::ipv4);
    const mdnspp::socket_options v6 = default_family_options<mdnspp::socket_options>(nic, address_family::ipv6);

    CHECK(v4.interface_index == v6.interface_index);
    CHECK(v4.multicast_group.address != v6.multicast_group.address);
}

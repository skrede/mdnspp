#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/interface_addresses.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <algorithm>
#include <string_view>

using namespace mdnspp;
using namespace mdnspp::detail;

namespace {

ip_address address(std::string_view text)
{
    return *parse_ip_address(text);
}

network_interface dual_stack_nic()
{
    network_interface nic;
    nic.name = "eth0";
    nic.addresses = {{address("192.0.2.5"), 24}, {address("2001:db8::5"), 64}, {address("fe80::5"), 64},
                     {address("198.51.100.5"), 24}};
    return nic;
}

}

TEST_CASE("prefix_from_netmask counts the mask bits of either family", "[interface_addresses]")
{
    CHECK(prefix_from_netmask(address("0.0.0.0")) == 0);
    CHECK(prefix_from_netmask(address("255.0.0.0")) == 8);
    CHECK(prefix_from_netmask(address("255.255.255.0")) == 24);
    CHECK(prefix_from_netmask(address("255.255.255.255")) == 32);
    CHECK(prefix_from_netmask(address("::")) == 0);
    CHECK(prefix_from_netmask(address("ffff:ffff:ffff:ffff::")) == 64);
    CHECK(prefix_from_netmask(address("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")) == 128);
}

TEST_CASE("address_before orders by family, then bytes, then prefix length", "[interface_addresses]")
{
    CHECK(address_before({address("203.0.113.1"), 24}, {address("::1"), 128}));
    CHECK(address_before({address("192.0.2.1"), 24}, {address("198.51.100.1"), 24}));
    CHECK(address_before({address("192.0.2.1"), 24}, {address("192.0.2.1"), 25}));
    CHECK_FALSE(address_before({address("192.0.2.1"), 24}, {address("192.0.2.1"), 24}));
    CHECK(address_before({address("2001:db8::1"), 64}, {address("fe80::1"), 64}));
}

TEST_CASE("first_address returns the first address of the family in vector order", "[interface_addresses]")
{
    const network_interface nic = dual_stack_nic();
    REQUIRE(first_address(nic, address_family::ipv4) != nullptr);
    CHECK(*first_address(nic, address_family::ipv4) == ip_network{address("192.0.2.5"), 24});
    REQUIRE(first_address(nic, address_family::ipv6) != nullptr);
    CHECK(*first_address(nic, address_family::ipv6) == ip_network{address("2001:db8::5"), 64});
    CHECK(first_address(network_interface{}, address_family::ipv4) == nullptr);
}

TEST_CASE("first_address prefers an IPv4 address outside 169.254/16 and falls back to link-local", "[interface_addresses]")
{
    network_interface nic;
    nic.addresses = {{address("169.254.1.1"), 16}, {address("fe80::1"), 64}, {address("192.168.1.1"), 24}};
    CHECK(*first_address(nic, address_family::ipv4) == ip_network{address("192.168.1.1"), 24});
    CHECK(*first_address(nic, address_family::ipv6) == ip_network{address("fe80::1"), 64});

    nic.addresses.erase(nic.addresses.begin() + 2);
    CHECK(*first_address(nic, address_family::ipv4) == ip_network{address("169.254.1.1"), 16});
    CHECK(*first_address(nic, address_family::ipv6) == ip_network{address("fe80::1"), 64});
}

TEST_CASE("has_family reports whether the interface has an address of the family", "[interface_addresses]")
{
    network_interface v4_only;
    v4_only.addresses = {{address("192.0.2.5"), 24}};
    CHECK(has_family(v4_only, address_family::ipv4));
    CHECK_FALSE(has_family(v4_only, address_family::ipv6));
    CHECK_FALSE(has_family(network_interface{}, address_family::ipv4));
}

TEST_CASE("contains matches an assigned address exactly, whatever its prefix", "[interface_addresses]")
{
    const network_interface nic = dual_stack_nic();
    CHECK(contains(nic, address("198.51.100.5")));
    CHECK(contains(nic, address("fe80::5")));
    CHECK_FALSE(contains(nic, address("192.0.2.6")));
    CHECK_FALSE(contains(nic, address("::ffff:192.0.2.5")));
}

TEST_CASE("clear_embedded_scope zeroes bytes 2 and 3 of a link-local address only", "[interface_addresses]")
{
    ip_address embedded = address("fe80:4::1");
    clear_embedded_scope(embedded);
    CHECK(embedded == address("fe80::1"));

    ip_address global = address("2001:db8::1");
    clear_embedded_scope(global);
    CHECK(global == address("2001:db8::1"));

    ip_address v4 = address("254.128.4.4");
    clear_embedded_scope(v4);
    CHECK(v4 == address("254.128.4.4"));
}

TEST_CASE("sorting by address_before puts IPv4 first and global IPv6 before link-local", "[interface_addresses]")
{
    network_interface nic = dual_stack_nic();
    std::ranges::sort(nic.addresses, address_before);
    CHECK(nic.addresses[0].address == address("192.0.2.5"));
    CHECK(nic.addresses[1].address == address("198.51.100.5"));
    CHECK(nic.addresses[2].address == address("2001:db8::5"));
    CHECK(nic.addresses[3].address == address("fe80::5"));
}

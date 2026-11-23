#include "interface_resolve_fixture.h"

#include "mdnspp/ip_address.h"
#include "mdnspp/service_info.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/interface_resolve.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <system_error>

using namespace mdnspp;
using namespace mdnspp::detail;

TEST_CASE("resolve_advertised_addresses is a no-op without auto_address", "[interface_resolve]")
{
    service_info info;
    resolve_advertised_addresses(test_interfaces(), {}, info);
    REQUIRE_FALSE(info.address_ipv4.has_value());
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses uses the bound interface", "[interface_resolve]")
{
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(test_interfaces(), {.index = 2}, info);
    REQUIRE(info.address_ipv4 == "10.0.0.2");
    REQUIRE(info.address_ipv6 == "fe80::2");
}

TEST_CASE("resolve_advertised_addresses never crosses interfaces for a missing family", "[interface_resolve]")
{
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(test_interfaces(), {.name = "eth1"}, info);
    REQUIRE(info.address_ipv4 == "10.0.1.3");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses preserves user-set fields", "[interface_resolve]")
{
    service_info info;
    info.auto_address = true;
    info.address_ipv4 = "192.0.2.1";
    resolve_advertised_addresses(test_interfaces(), {.index = 2}, info);
    REQUIRE(info.address_ipv4 == "192.0.2.1");
    REQUIRE(info.address_ipv6 == "fe80::2");
}

TEST_CASE("resolve_advertised_addresses uses an address-only binding verbatim", "[interface_resolve]")
{
    // The bound link is not in the enumerated list (e.g. an inproc or
    // container interface): the binding address itself is the announcing
    // link's address for its family.
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(test_interfaces(), {.address = "172.16.0.9"}, info);
    REQUIRE(info.address_ipv4 == "172.16.0.9");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses unbound falls back to the lowest-index candidate", "[interface_resolve]")
{
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(test_interfaces(), {}, info);
    REQUIRE(info.address_ipv4 == "10.0.0.2");
    REQUIRE(info.address_ipv6 == "fe80::2");
}

TEST_CASE("resolve_advertised_addresses leaves a family with no candidate unset", "[interface_resolve]")
{
    std::vector<network_interface> v4_only{
        make_nic(1, "lo", "127.0.0.1", "::1", true),
        make_nic(2, "eth0", "10.0.0.2"),
    };
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(v4_only, {}, info);
    REQUIRE(info.address_ipv4 == "10.0.0.2");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("select_interface passes an IPv4 address binding to the kernel by value", "[interface_resolve]")
{
    auto nics = test_interfaces();
    std::error_code ec;

    resolved_interface listed = select_interface(nics, {.address = "10.0.1.3"}, address_family::ipv4, ec);
    REQUIRE_FALSE(ec);
    REQUIRE(listed.index == 3);
    REQUIRE(listed.ipv4 == parse_ip_address("10.0.1.3"));

    resolved_interface unlisted = select_interface(nics, {.address = "192.0.2.7"}, address_family::ipv4, ec);
    REQUIRE_FALSE(ec);
    REQUIRE(unlisted.index == 0);
    REQUIRE(unlisted.ipv4 == parse_ip_address("192.0.2.7"));
}

TEST_CASE("select_interface resolves an IPv6 address binding to the interface carrying it", "[interface_resolve]")
{
    auto nics = test_interfaces();
    std::error_code ec;

    REQUIRE(select_interface(nics, {.address = "fe80::4"}, address_family::ipv6, ec).index == 4);
    REQUIRE_FALSE(ec);
    for(const char *rejected : {"2001:db8::dead", "10.0.0.2", "not an address"})
    {
        CAPTURE(rejected);
        REQUIRE(select_interface(nics, {.address = rejected}, address_family::ipv6, ec).index == 0);
        REQUIRE(ec == std::errc::invalid_argument);
    }
    select_interface(nics, {.address = "fe80::2"}, address_family::ipv4, ec);
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("select_interface matches any text form of an IPv6 interface address", "[interface_resolve]")
{
    auto nics = test_interfaces();
    std::error_code ec;

    for(const char *loopback : {"0:0:0:0:0:0:0:1", "::1", "0000:0000:0000:0000:0000:0000:0000:0001"})
    {
        CAPTURE(loopback);
        REQUIRE(select_interface(nics, {.address = loopback}, address_family::ipv6, ec).index == 1);
        REQUIRE_FALSE(ec);
    }
    for(const char *link_local : {"FE80::4", "fe80:0000:0000:0000:0000:0000:0000:0004", "fe80:0:0:0::4"})
    {
        CAPTURE(link_local);
        REQUIRE(select_interface(nics, {.address = link_local}, address_family::ipv6, ec).index == 4);
        REQUIRE_FALSE(ec);
    }
}

TEST_CASE("select_interface honors the zone of a scoped IPv6 address binding", "[interface_resolve]")
{
    std::vector<network_interface> nics{make_nic(7, "eth7", {}, "fe80::7"), make_nic(8, "eth8", {}, "fe80::7")};
    std::error_code ec;

    REQUIRE(select_interface(nics, {.address = "fe80::7%8"}, address_family::ipv6, ec).index == 8);
    REQUIRE_FALSE(ec);
    REQUIRE(select_interface(nics, {.address = "fe80::7%7"}, address_family::ipv6, ec).index == 7);
    REQUIRE_FALSE(ec);
    select_interface(nics, {.address = "fe80::7%9"}, address_family::ipv6, ec);
    REQUIRE(ec == std::errc::invalid_argument);
}

#include "interface_resolve_fixture.h"

#include "mdnspp/service_info.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/interface_resolve.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>

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

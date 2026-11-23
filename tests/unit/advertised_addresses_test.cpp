#include "interface_resolve_fixture.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/interface_resolve.h"
#include "mdnspp/detail/advertised_addresses.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstdint>
#include <system_error>

using namespace mdnspp;
using namespace mdnspp::detail;

namespace {

const endpoint ipv4_group{"224.0.0.251", 5353};
const endpoint ipv6_group{"ff02::fb", 5353};

service_info resolved(const interface_binding &binding, const announcing_link &link, service_info info = {})
{
    info.auto_address = true;
    resolve_advertised_addresses(binding, link, info);
    return info;
}

service_info resolved_bound(const std::vector<network_interface> &nics, const interface_binding &binding,
                            uint32_t pinned_index = 0)
{
    std::error_code ec;
    const announcing_link link = select_announcing_link(nics, binding, pinned_index, ipv4_group, ec);
    REQUIRE_FALSE(ec);
    return resolved(binding, link);
}

}

TEST_CASE("resolve_advertised_addresses is a no-op without auto_address", "[interface_resolve]")
{
    const std::vector<network_interface> nics = test_interfaces();
    service_info info;
    resolve_advertised_addresses({}, {&nics[1], true}, info);
    REQUIRE_FALSE(info.address_ipv4.has_value());
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses uses the bound interface", "[interface_resolve]")
{
    const service_info info = resolved_bound(test_interfaces(), {.index = 2});
    REQUIRE(info.address_ipv4 == "10.0.0.2");
    REQUIRE(info.address_ipv6 == "fe80::2");
}

TEST_CASE("resolve_advertised_addresses never crosses interfaces for a missing family", "[interface_resolve]")
{
    const service_info info = resolved_bound(test_interfaces(), {.name = "eth1"});
    REQUIRE(info.address_ipv4 == "10.0.1.3");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses preserves user-set fields", "[interface_resolve]")
{
    const std::vector<network_interface> nics = test_interfaces();
    service_info user;
    user.address_ipv4 = "192.0.2.1";
    const service_info info = resolved({.index = 2}, {&nics[1], true}, user);
    REQUIRE(info.address_ipv4 == "192.0.2.1");
    REQUIRE(info.address_ipv6 == "fe80::2");
}

TEST_CASE("resolve_advertised_addresses uses an address-only binding verbatim", "[interface_resolve]")
{
    // The bound link is not in the enumerated list (e.g. an inproc or
    // container interface): the binding address itself is the announcing
    // link's address for its family.
    const service_info info = resolved_bound(test_interfaces(), {.address = "172.16.0.9"});
    REQUIRE(info.address_ipv4 == "172.16.0.9");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses unbound uses the egress interface", "[interface_resolve]")
{
    std::vector<network_interface> nics = test_interfaces();
    nics.push_back(make_nic(6, "eth3", "10.0.3.6", "fe80::6"));
    const service_info info = resolved({}, {&nics.back(), true});
    REQUIRE(info.address_ipv4 == "10.0.3.6");
    REQUIRE(info.address_ipv6 == "fe80::6");
}

TEST_CASE("resolve_advertised_addresses leaves a family with no candidate unset", "[interface_resolve]")
{
    const std::vector<network_interface> nics = test_interfaces();
    const service_info info = resolved({}, {&nics[2], true});
    REQUIRE(info.address_ipv4 == "10.0.1.3");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses advertises nothing without an egress interface", "[interface_resolve]")
{
    const service_info info = resolved({}, {nullptr, true});
    REQUIRE_FALSE(info.address_ipv4.has_value());
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("an unpinned IPv6 socket advertises the egress IPv4 address and no IPv6 address", "[interface_resolve]")
{
    const std::vector<network_interface> nics = test_interfaces();
    std::error_code ec;
    REQUIRE_FALSE(select_announcing_link(nics, {}, 0, ipv6_group, ec).ipv6_valid);
    REQUIRE(select_announcing_link(nics, {}, 0, ipv4_group, ec).ipv6_valid);

    const service_info info = resolved({}, {&nics[1], false});
    REQUIRE(info.address_ipv4 == "10.0.0.2");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("an unbound socket pinned to an interface announces on that interface", "[interface_resolve]")
{
    const service_info info = resolved_bound(test_interfaces(), {}, 4);
    REQUIRE_FALSE(info.address_ipv4.has_value());
    REQUIRE(info.address_ipv6 == "fe80::4");
}

TEST_CASE("a bound socket announces on its binding whatever it is pinned to", "[interface_resolve]")
{
    const service_info info = resolved_bound(test_interfaces(), {.name = "eth1"}, 4);
    REQUIRE(info.address_ipv4 == "10.0.1.3");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

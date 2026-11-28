#include "interface_resolve_fixture.h"

#include "support/skip_or_fail.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/egress_interface.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <optional>
#include <system_error>

using namespace mdnspp;
using namespace mdnspp::detail;

TEST_CASE("the egress source address of the mDNS group belongs to an enumerated interface", "[egress]")
{
    std::error_code ec;
    const std::optional<ip_address> source = egress_source_address(endpoint{"224.0.0.251", 5353}, ec);
    if(!source.has_value())
        test_support::skip_or_fail("no route to the mDNS group: " + ec.message());
    REQUIRE_FALSE(ec);

    const std::vector<network_interface> interfaces = enumerate_interfaces();
    const network_interface *nic = egress_interface(interfaces, *source);
    REQUIRE(nic != nullptr);
    INFO("egress interface: " << nic->name);
    CHECK(egress_source_address(endpoint{"ff02::fb", 5353}, ec) == source);
    CHECK_FALSE(ec);
}

TEST_CASE("egress_interface finds the interface carrying the source address", "[egress]")
{
    const std::vector<network_interface> nics = test_interfaces();
    REQUIRE(egress_interface(nics, *parse_ip_address("10.0.1.3")) == &nics[2]);
    REQUIRE(egress_interface(nics, *parse_ip_address("fe80::4")) == &nics[3]);
    REQUIRE(egress_interface(nics, *parse_ip_address("192.0.2.1")) == nullptr);
}

TEST_CASE("egress_source_address rejects a group that is not an IP address", "[egress]")
{
    std::error_code ec;
    REQUIRE_FALSE(egress_source_address(endpoint{"not an address", 5353}, ec).has_value());
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("connected_source reports a failed connect instead of returning an empty result silently", "[egress]")
{
    std::error_code ec;
    REQUIRE_FALSE(connected_source(invalid_socket, endpoint{"224.0.0.251", 5353}, ec).has_value());
    REQUIRE(ec);
}

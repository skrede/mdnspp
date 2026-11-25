#include "netns/helpers.h"
#include "netns/bound_peers.h"

#include "support/netns.h"
#include "support/ipv6_interface.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_server.h"

#include "mdnspp/default/default_policy.h"

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/egress_interface.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <variant>
#include <optional>
#include <algorithm>
#include <system_error>

using mdnspp::test_support::netns_interface_index;
using mdnspp::test_support::require_netns_harness;

namespace {

struct advertised
{
    std::vector<std::string> ipv4;
    std::vector<std::string> ipv6;
};

mdnspp::service_info egress_service()
{
    mdnspp::service_info info;
    info.service_name = "Egress._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "egress.local.";
    info.port = 8080;
    info.auto_address = true;
    return info;
}

mdnspp::observer_options capture_into(advertised &seen)
{
    auto record = [&seen](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &rec)
    {
        const mdnspp::dns_name host{"egress.local."};
        if(const auto *a = std::get_if<mdnspp::record_a>(&rec); a != nullptr && a->name == host)
            seen.ipv4.push_back(a->address_string);
        if(const auto *aaaa = std::get_if<mdnspp::record_aaaa>(&rec); aaaa != nullptr && aaaa->name == host)
            seen.ipv6.push_back(aaaa->address_string);
    };
    return mdnspp::observer_options{.on_record = record};
}

advertised advertised_by_unbound_server(const std::string &group)
{
    mdnspp::default_context ctx;
    advertised seen;
    mdnspp::basic_observer<mdnspp::default_policy> observer{ctx, capture_into(seen), bound_to("d1", group)};
    observer.async_observe();
    mdnspp::basic_service_server<mdnspp::default_policy> server{
        ctx, egress_service(), mdnspp::service_options{},
        mdnspp::socket_options{.multicast_group = mdnspp::endpoint{group, mdns_port}}};
    server.async_start();
    run_for(ctx, std::chrono::milliseconds{1500});
    return seen;
}

std::vector<std::string> ipv6_addresses_of(const std::string &device)
{
    std::vector<std::string> addresses;
    for(const mdnspp::network_interface &nic : mdnspp::enumerate_interfaces())
        for(const mdnspp::ip_network &net : nic.addresses)
            if(nic.name == device && net.address.family == mdnspp::address_family::ipv6)
                addresses.push_back(mdnspp::detail::format_ip_address(net.address));
    return addresses;
}

void require_advertised_d1(const advertised &seen)
{
    const std::vector<std::string> d1_ipv6 = ipv6_addresses_of("d1");
    REQUIRE_FALSE(seen.ipv4.empty());
    REQUIRE_FALSE(seen.ipv6.empty());
    for(const std::string &address : seen.ipv4)
        CHECK(address == "10.20.1.1");
    for(const std::string &address : seen.ipv6)
    {
        CAPTURE(address);
        CHECK(std::ranges::find(d1_ipv6, address) != d1_ipv6.end());
    }
}

}

TEST_CASE("an unbound IPv4 server advertises the addresses of the interface the kernel sends on", "[netns][egress]")
{
    require_netns_harness();
    REQUIRE(netns_interface_index("d0") < netns_interface_index("d1"));
    require_advertised_d1(advertised_by_unbound_server("224.0.0.251"));
}

TEST_CASE("an unbound IPv6 server advertises the addresses of the IPv4 egress interface", "[netns][egress]")
{
    require_netns_harness();
    require_advertised_d1(advertised_by_unbound_server("ff02::fb"));
}

TEST_CASE("an unbound IPv6 default_socket is pinned to the IPv4 egress interface", "[netns][egress][ipv6]")
{
    require_netns_harness();
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket socket{ctx, mdnspp::test_support::ipv6_group_options(), ec};
    REQUIRE_FALSE(ec);

    const uint32_t d1 = netns_interface_index("d1");
    CHECK(socket.interface_index() == d1);
    CHECK(mdnspp::test_support::ipv6_multicast_interface(socket.native_handle()) == d1);
    CHECK(joined_mdns_group("d1"));
    CHECK_FALSE(joined_mdns_group("d0"));
}

TEST_CASE("the egress lookup follows the route of the IPv4 group and reports a missing route as an error",
          "[netns][egress]")
{
    require_netns_harness();
    const mdnspp::ip_address d1 = *mdnspp::detail::parse_ip_address("10.20.1.1");
    std::error_code ec;
    CHECK(mdnspp::detail::egress_source_address({"224.0.0.251", mdns_port}, ec) == d1);
    CHECK(mdnspp::detail::egress_source_address({"ff02::fb", mdns_port}, ec) == d1);
    CHECK_FALSE(ec);

    std::optional<mdnspp::ip_address> unrouted;
    ec = std::make_error_code(std::errc::interrupted);
    mdnspp::test_support::run_in_netns("p0", [&]
    {
        unrouted = mdnspp::detail::egress_source_address({"224.0.0.251", mdns_port}, ec);
    });
    CHECK_FALSE(unrouted.has_value());
    CHECK(ec == std::errc::network_unreachable);
}

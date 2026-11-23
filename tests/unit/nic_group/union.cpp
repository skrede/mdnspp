#include "fixture.h"
#include "raw_sender.h"

#include "mdnspp/inproc/inproc_socket_options.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>

namespace {

using address_list = std::vector<std::string>;

address_list sorted(address_list addresses)
{
    std::ranges::sort(addresses);
    return addresses;
}

std::vector<resolved_service> discover(group_fixture &f, group_options grp_opts, const auto &send)
{
    monitor_group grp{f.executor, std::move(grp_opts), one_monitor()};
    f.start_watching(grp);
    send();
    f.advance(200ms);
    std::vector<resolved_service> services = grp.services();
    grp.stop();
    return services;
}

std::vector<resolved_service> discover_split_families(group_fixture &f, dedup_mode mode)
{
    use_dual_stack_nics(f);
    family_senders senders{f.executor};
    group_options grp_opts = f.make_grp_opts();
    grp_opts.dedup = mode;
    return discover(f, std::move(grp_opts), [&]
    {
        senders.ipv4.send({.ipv4 = "192.0.2.10"});
        senders.ipv6.send({.ipv6 = "2001:db8::10"});
    });
}

endpoint own_ipv4_group(uint32_t index)
{
    return endpoint{"239.255.0." + std::to_string(index), 5353};
}

}

TEST_CASE("nic_group merged services unite the addresses each family found", "[nic_group][family]")
{
    group_fixture f;
    const std::vector<resolved_service> services = discover_split_families(f, dedup_mode::merged);

    REQUIRE(services.size() == 1);
    CHECK(services[0].ipv4_addresses == address_list{"192.0.2.10"});
    CHECK(services[0].ipv6_addresses == address_list{"2001:db8::10"});
}

TEST_CASE("nic_group per-interface services unite the families of each NIC", "[nic_group][family]")
{
    group_fixture f;
    const std::vector<resolved_service> services = discover_split_families(f, dedup_mode::per_interface);

    REQUIRE(services.size() == 2);
    CHECK(services[0].source_interface.name != services[1].source_interface.name);
    for(const resolved_service &svc : services)
    {
        CHECK(svc.ipv4_addresses == address_list{"192.0.2.10"});
        CHECK(svc.ipv6_addresses == address_list{"2001:db8::10"});
    }
}

TEST_CASE("nic_group merged services unite the addresses of every NIC", "[nic_group]")
{
    group_fixture f;
    group_options grp_opts = f.make_grp_opts();
    grp_opts.socket_options_factory = [](const network_interface &nic, address_family)
    {
        inproc::inproc_socket_options opts;
        opts.multicast_group = own_ipv4_group(nic.index);
        return opts;
    };
    group_sender nic1{f.executor, own_ipv4_group(1).address};
    group_sender nic2{f.executor, own_ipv4_group(2).address};
    const std::vector<resolved_service> services = discover(f, std::move(grp_opts), [&]
    {
        nic1.send({.ipv4 = "192.0.2.10"});
        nic2.send({.ipv4 = "192.0.2.20"});
    });

    REQUIRE(services.size() == 1);
    CHECK(sorted(services[0].ipv4_addresses) == address_list{"192.0.2.10", "192.0.2.20"});
}

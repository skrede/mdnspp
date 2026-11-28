#include "fixture.h"
#include "sniffer.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <utility>

namespace {

void use_only(group_fixture &f, network_interface nic)
{
    f.nics->clear();
    f.nics->push_back(std::move(nic));
}

void serve(group_fixture &f, server_group &grp)
{
    grp.start();
    f.executor.drain();
    f.advance_to_live();
}

}

TEST_CASE("nic_group probes only the IPv6 group over an IPv6-only NIC", "[nic_group][family]")
{
    group_fixture f;
    family_traffic traffic{f.executor};
    use_only(f, make_nic(1, "nic1", {"fd00::1", "fe80::1"}));
    server_group grp{f.executor, f.make_grp_opts(), one_server()};
    serve(f, grp);

    CHECK(traffic.ipv6.queries > 0);
    CHECK(traffic.ipv4.queries == 0);
    grp.stop();
}

TEST_CASE("nic_group probes both groups over a dual-stack NIC", "[nic_group][family]")
{
    group_fixture f;
    family_traffic traffic{f.executor};
    use_only(f, make_nic(1, "nic1", {"10.0.0.1", "fd00::1"}));
    server_group grp{f.executor, f.make_grp_opts(), one_server()};
    serve(f, grp);

    CHECK(traffic.ipv4.queries > 0);
    CHECK(traffic.ipv6.queries > 0);
    grp.stop();
}

TEST_CASE("nic_group probes only the IPv4 group over an IPv4-only NIC", "[nic_group][family]")
{
    group_fixture f;
    family_traffic traffic{f.executor};
    use_only(f, make_nic(1, "nic1", "10.0.0.1"));
    server_group grp{f.executor, f.make_grp_opts(), one_server()};
    serve(f, grp);

    CHECK(traffic.ipv4.queries > 0);
    CHECK(traffic.ipv6.queries == 0);
    grp.stop();
}

TEST_CASE("nic_group calls the socket options factory once per family the NIC has", "[nic_group][family]")
{
    group_fixture f;
    family_traffic traffic{f.executor};
    std::vector<std::pair<std::string, address_family>> calls;
    auto grp_opts = f.make_grp_opts();
    grp_opts.socket_options_factory = [&calls](const network_interface &nic, address_family family)
    {
        calls.emplace_back(nic.name, family);
        inproc::inproc_socket_options opts;
        opts.interface_index = nic.index;
        if(family == address_family::ipv6)
            opts.multicast_group = endpoint{ipv6_group, 5353};
        return opts;
    };
    use_only(f, make_nic(1, "nic1", {"10.0.0.1", "fd00::1"}));
    server_group grp{f.executor, std::move(grp_opts), one_server()};
    serve(f, grp);

    using call = std::pair<std::string, address_family>;
    CHECK(calls == std::vector<call>{{"nic1", address_family::ipv4}, {"nic1", address_family::ipv6}});
    CHECK(traffic.ipv4.queries > 0);
    CHECK(traffic.ipv6.queries > 0);
    grp.stop();
}

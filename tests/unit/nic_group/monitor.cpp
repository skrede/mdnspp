#include "fixture.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>
#include <vector>
#include <algorithm>

TEST_CASE("nic_group fires interface-stamped on_found once per NIC", "[nic_group]")
{
    group_fixture f;
    found_list found;
    monitor_group grp{f.executor, f.recording_grp_opts(found), one_monitor()};
    f.start_watching(grp);
    announced_service svc{f};

    // One service reachable on two interfaces: two events, no deduplication.
    REQUIRE(found.size() == 2);
    REQUIRE(sorted_interfaces(found) == std::vector<std::string>{"nic1", "nic2"});
    REQUIRE(found[0].second == "svc._test._tcp.local.");
    REQUIRE(found[1].second == "svc._test._tcp.local.");
    grp.stop();
}

TEST_CASE("nic_group services() snapshot honors dedup_mode", "[nic_group]")
{
    group_fixture f;
    auto grp_opts = f.make_grp_opts();
    const auto mode = GENERATE(dedup_mode::merged, dedup_mode::per_interface);
    grp_opts.dedup = mode;
    monitor_group grp{f.executor, std::move(grp_opts), one_monitor()};
    f.start_watching(grp);
    announced_service svc{f};

    auto services = grp.services();
    if(mode == dedup_mode::merged)
    {
        REQUIRE(services.size() == 1);
        REQUIRE(services[0].instance_name.str() == "svc._test._tcp.local.");
    }
    else
    {
        REQUIRE(services.size() == 2);
        std::vector<std::string> interfaces{services[0].source_interface.name, services[1].source_interface.name};
        std::ranges::sort(interfaces);
        REQUIRE(interfaces == std::vector<std::string>{"nic1", "nic2"});
    }
    grp.stop();
}

TEST_CASE("nic_group interface_filter suppresses per-NIC instances", "[nic_group]")
{
    group_fixture f;
    found_list found;
    auto grp_opts = f.recording_grp_opts(found);
    grp_opts.interface_filter = [](const network_interface &nic) { return nic.name == "nic1"; };
    monitor_group grp{f.executor, std::move(grp_opts), one_monitor()};
    f.start_watching(grp);
    announced_service svc{f};

    REQUIRE(sorted_interfaces(found) == std::vector<std::string>{"nic1"});
    grp.stop();
}

TEST_CASE("nic_group wires runtime-added NICs to the group-level callbacks", "[nic_group]")
{
    group_fixture f;
    f.nics->pop_back();
    found_list found;
    monitor_group grp{f.executor, f.recording_grp_opts(found), one_monitor()};
    f.start_watching(grp);

    f.nics->push_back(make_nic(2, "nic2", "10.0.1.1"));
    f.advance(100ms); // one poll_interval
    f.executor.drain();
    announced_service svc{f};

    REQUIRE(found.size() == 2);
    REQUIRE(sorted_interfaces(found) == std::vector<std::string>{"nic1", "nic2"});
    grp.stop();
}

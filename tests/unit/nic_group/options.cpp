#include "fixture.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/observer_options.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <utility>
#include <system_error>

TEST_CASE("nic_group rejects callback-bearing per-NIC monitor options", "[nic_group]")
{
    group_fixture f;
    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{
        .on_found = [](const resolved_service &) {},
    });

    try
    {
        monitor_group grp{f.executor, f.make_grp_opts(), std::move(mon_opts)};
        FAIL("expected std::system_error");
    }
    catch(const std::system_error &e)
    {
        REQUIRE(e.code() == std::errc::invalid_argument);
    }
}

TEST_CASE("nic_group rejects callback-bearing per-NIC observer options", "[nic_group]")
{
    group_fixture f;
    std::vector<observer_options> obs_opts;
    obs_opts.push_back(observer_options{
        .on_record = [](const endpoint &, const mdns_record_variant &) {},
    });

    try
    {
        observer_group grp{f.executor, f.make_grp_opts(), std::move(obs_opts)};
        FAIL("expected std::system_error");
    }
    catch(const std::system_error &e)
    {
        REQUIRE(e.code() == std::errc::invalid_argument);
    }
}

TEST_CASE("nic_group start is a no-op while running and stop is idempotent", "[nic_group]")
{
    group_fixture f;
    found_list found;
    monitor_group grp{f.executor, f.recording_grp_opts(found), one_monitor()};
    grp.watch("_test._tcp.local.");
    grp.start();
    grp.start();
    f.executor.drain();
    announced_service svc{f};

    REQUIRE(found.size() == 2); // one event per NIC, not four
    grp.stop();
    grp.stop();
}

TEST_CASE("nic_group restart starts with fresh caches and a monitor on every NIC", "[nic_group]")
{
    group_fixture f;
    found_list found;
    monitor_group grp{f.executor, f.recording_grp_opts(found), one_monitor()};
    f.start_watching(grp);
    {
        announced_service first{f};
        REQUIRE(sorted_interfaces(found) == std::vector<std::string>{"nic1", "nic2"});
        grp.stop();
    }

    found.clear();
    grp.start();
    f.executor.drain();
    REQUIRE(grp.services().empty());

    announced_service svc{f};
    REQUIRE(sorted_interfaces(found) == std::vector<std::string>{"nic1", "nic2"});
    const std::vector<resolved_service> services = grp.services();
    REQUIRE(services.size() == 1);
    REQUIRE(services[0].instance_name.str() == "svc._test._tcp.local.");
    grp.stop();
}

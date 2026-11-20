#include "fixture.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/observer_options.h"

#include <catch2/catch_test_macros.hpp>

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

TEST_CASE("nic_group start is a no-op while running and restarts after stop", "[nic_group]")
{
    group_fixture f;
    found_list found;
    monitor_group grp{f.executor, f.recording_grp_opts(found), one_monitor()};
    grp.watch("_test._tcp.local.");
    grp.start();
    grp.start(); // no-op: instances must not be duplicated
    f.executor.drain();
    announced_service svc{f};

    REQUIRE(found.size() == 2); // one event per NIC, not four
    grp.stop();
    grp.stop(); // idempotent

    found.clear();
    grp.start();
    f.executor.drain();
    REQUIRE(grp.services().empty());
    grp.stop();
}

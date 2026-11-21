#include "fixture.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/observer_options.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <utility>
#include <system_error>

namespace {

using dynamic_group = basic_dynamic_nic_group<inproc_test_policy>;

void monitor_and_start(group_fixture &f, dynamic_group &grp)
{
    grp.monitor(one_monitor());
    grp.start();
    grp.watch("_test._tcp.local.");
    f.executor.drain();
}

template <typename Call>
void require_invalid_argument(Call call)
{
    try
    {
        call();
        FAIL("expected std::system_error");
    }
    catch(const std::system_error &e)
    {
        REQUIRE(e.code() == std::errc::invalid_argument);
    }
}

}

TEST_CASE("dynamic_nic_group wires group-level callbacks with interface stamping", "[nic_group][dynamic]")
{
    group_fixture f;
    found_list found;
    dynamic_group grp{f.executor, f.recording_grp_opts(found)};
    monitor_and_start(f, grp);
    announced_service svc{f};

    REQUIRE(found.size() == 2);
    REQUIRE(sorted_interfaces(found) == std::vector<std::string>{"nic1", "nic2"});

    grp.stop();
}

TEST_CASE("dynamic_nic_group start is idempotent", "[nic_group][dynamic]")
{
    group_fixture f;
    found_list found;
    dynamic_group grp{f.executor, f.recording_grp_opts(found)};
    grp.monitor(one_monitor());
    grp.start();
    grp.start();
    grp.start();
    grp.watch("_test._tcp.local.");
    f.executor.drain();
    announced_service svc{f};

    REQUIRE(found.size() == 2); // one event per NIC, not per start() call

    grp.stop();
}

TEST_CASE("dynamic_nic_group services() returns the merged snapshot", "[nic_group][dynamic]")
{
    group_fixture f;
    dynamic_group grp{f.executor, f.make_grp_opts()};

    REQUIRE(grp.services().empty()); // pre-start: no impl, empty result

    monitor_and_start(f, grp);
    announced_service svc{f};

    auto services = grp.services();
    REQUIRE(services.size() == 1); // merged across both NICs
    REQUIRE(services[0].instance_name.str() == "svc._test._tcp.local.");

    grp.stop();
}

TEST_CASE("dynamic_nic_group rejects callback-bearing per-NIC options", "[nic_group][dynamic]")
{
    group_fixture f;
    dynamic_group grp{f.executor, f.make_grp_opts()};

    SECTION("monitor options with callbacks")
    {
        std::vector<monitor_options> mon_opts;
        mon_opts.push_back(monitor_options{
            .on_found = [](const resolved_service &) {},
        });
        require_invalid_argument([&] { grp.monitor(std::move(mon_opts)); });
    }

    SECTION("observer options with callbacks")
    {
        std::vector<observer_options> obs_opts;
        obs_opts.push_back(observer_options{
            .on_record = [](const endpoint &, const mdns_record_variant &) {},
        });
        require_invalid_argument([&] { grp.observe(std::move(obs_opts)); });
    }
}

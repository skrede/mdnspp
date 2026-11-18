// basic_dynamic_nic_group unit tests over the deterministic inproc bus.
//
// Verifies that the runtime-composed group obeys the same callback contract
// as basic_nic_group: group-level interface-stamped callbacks, rejection of
// callback-bearing per-NIC options, and an idempotent start().

#include "mdnspp/inproc/inproc_policy.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/basic_nic_group.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_server.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <system_error>

using namespace mdnspp;
using mdnspp::testing::test_clock;
using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_executor;

namespace {

network_interface make_nic(uint32_t index, std::string name, std::string ipv4)
{
    network_interface nic;
    nic.name = std::move(name);
    nic.ipv4_address = std::move(ipv4);
    nic.index = index;
    nic.is_up = true;
    return nic;
}

service_info make_service(std::string name)
{
    service_info info;
    info.service_name = std::move(name);
    info.service_type = "_test._tcp.local.";
    info.hostname     = "host.local.";
    info.port         = 8080;
    info.address_ipv4 = "192.168.1.1";
    return info;
}

struct dynamic_fixture
{
    dynamic_fixture()
    {
        test_clock::reset();
        nics->push_back(make_nic(1, "nic1", "10.0.0.1"));
        nics->push_back(make_nic(2, "nic2", "10.0.1.1"));
    }

    basic_nic_group_options<inproc_test_policy> make_grp_opts()
    {
        basic_nic_group_options<inproc_test_policy> opts;
        opts.monitor_opts.poll_interval = std::chrono::milliseconds{100};
        opts.monitor_opts.enumerator = [nics = nics](std::error_code &ec)
        {
            ec.clear();
            return *nics;
        };
        return opts;
    }

    void advance(std::chrono::milliseconds d)
    {
        test_clock::advance(d);
        executor.drain();
    }

    void advance_to_live()
    {
        advance(std::chrono::milliseconds{250});
        advance(std::chrono::milliseconds{250});
        advance(std::chrono::milliseconds{250});
        advance(std::chrono::milliseconds{250});
        advance(std::chrono::milliseconds{1000});
    }

    inproc_bus<test_clock> bus;
    inproc_executor<test_clock> executor{bus};
    std::shared_ptr<std::vector<network_interface>> nics{
        std::make_shared<std::vector<network_interface>>()};
};

}

TEST_CASE("dynamic_nic_group wires group-level callbacks with interface stamping", "[nic_group][dynamic]")
{
    dynamic_fixture f;

    std::vector<std::pair<std::string, std::string>> found;
    auto grp_opts = f.make_grp_opts();
    grp_opts.on_found = [&](const network_interface &nic, const resolved_service &svc)
    {
        found.emplace_back(nic.name, svc.instance_name.str());
    };

    basic_dynamic_nic_group<inproc_test_policy> grp{f.executor, std::move(grp_opts)};

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{});
    grp.monitor(std::move(mon_opts));

    grp.start();
    grp.watch("_test._tcp.local.");
    f.executor.drain();

    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    REQUIRE(found.size() == 2);
    std::vector<std::string> interfaces{found[0].first, found[1].first};
    std::ranges::sort(interfaces);
    REQUIRE(interfaces == std::vector<std::string>{"nic1", "nic2"});

    grp.stop();
}

TEST_CASE("dynamic_nic_group start is idempotent", "[nic_group][dynamic]")
{
    dynamic_fixture f;

    std::vector<std::string> found_interfaces;
    auto grp_opts = f.make_grp_opts();
    grp_opts.on_found = [&](const network_interface &nic, const resolved_service &)
    {
        found_interfaces.push_back(nic.name);
    };

    basic_dynamic_nic_group<inproc_test_policy> grp{f.executor, std::move(grp_opts)};

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{});
    grp.monitor(std::move(mon_opts));

    grp.start();
    grp.start(); // second call must not rebuild the impl or duplicate instances
    grp.start();
    grp.watch("_test._tcp.local.");
    f.executor.drain();

    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    REQUIRE(found_interfaces.size() == 2); // one event per NIC, not per start() call

    grp.stop();
}

TEST_CASE("dynamic_nic_group services() returns the merged snapshot", "[nic_group][dynamic]")
{
    dynamic_fixture f;

    basic_dynamic_nic_group<inproc_test_policy> grp{f.executor, f.make_grp_opts()};

    REQUIRE(grp.services().empty()); // pre-start: no impl, empty result

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{});
    grp.monitor(std::move(mon_opts));

    grp.start();
    grp.watch("_test._tcp.local.");
    f.executor.drain();

    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    auto services = grp.services();
    REQUIRE(services.size() == 1); // merged across both NICs
    REQUIRE(services[0].instance_name.str() == "svc._test._tcp.local.");

    grp.stop();
}

TEST_CASE("dynamic_nic_group rejects callback-bearing per-NIC options", "[nic_group][dynamic]")
{
    dynamic_fixture f;

    basic_dynamic_nic_group<inproc_test_policy> grp{f.executor, f.make_grp_opts()};

    SECTION("monitor options with callbacks")
    {
        std::vector<monitor_options> mon_opts;
        mon_opts.push_back(monitor_options{
            .on_found = [](const resolved_service &) {},
        });

        try
        {
            grp.monitor(std::move(mon_opts));
            FAIL("expected std::system_error");
        }
        catch(const std::system_error &e)
        {
            REQUIRE(e.code() == std::errc::invalid_argument);
        }
    }

    SECTION("observer options with callbacks")
    {
        std::vector<observer_options> obs_opts;
        obs_opts.push_back(observer_options{
            .on_record = [](const endpoint &, const mdns_record_variant &) {},
        });

        try
        {
            grp.observe(std::move(obs_opts));
            FAIL("expected std::system_error");
        }
        catch(const std::system_error &e)
        {
            REQUIRE(e.code() == std::errc::invalid_argument);
        }
    }
}

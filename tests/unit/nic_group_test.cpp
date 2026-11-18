// basic_nic_group unit tests over the deterministic inproc bus.
//
// The nic_monitor_options::enumerator seam supplies a fixed, test-controlled
// interface list, so per-NIC instance creation and the interface-stamped
// group-level callbacks can be exercised without OS interface enumeration.
// All per-NIC sockets register on one shared inproc bus; multicast traffic is
// therefore visible to every per-NIC instance, mimicking a service reachable
// on every interface.

#include "mdnspp/inproc/inproc_policy.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/basic_nic_group.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

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

struct group_fixture
{
    group_fixture()
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

    // Step a basic_service_server (default service_options) from async_start
    // through probe and announce to live state.
    void advance_to_live()
    {
        advance(std::chrono::milliseconds{250}); // initial probe delay upper bound
        advance(std::chrono::milliseconds{250}); // probe 2
        advance(std::chrono::milliseconds{250}); // probe 3
        advance(std::chrono::milliseconds{250}); // conflict window
        advance(std::chrono::milliseconds{1000}); // second announcement
    }

    inproc_bus<test_clock> bus;
    inproc_executor<test_clock> executor{bus};
    std::shared_ptr<std::vector<network_interface>> nics{
        std::make_shared<std::vector<network_interface>>()};
};

}

TEST_CASE("nic_group fires interface-stamped on_found once per NIC", "[nic_group]")
{
    group_fixture f;

    std::vector<std::pair<std::string, std::string>> found; // (interface, instance)
    auto grp_opts = f.make_grp_opts();
    grp_opts.on_found = [&](const network_interface &nic, const resolved_service &svc)
    {
        found.emplace_back(nic.name, svc.instance_name.str());
    };

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{});

    basic_nic_group<inproc_test_policy, basic_service_monitor> grp{
        f.executor, std::move(grp_opts), std::move(mon_opts)};
    grp.watch("_test._tcp.local.");
    grp.start();
    f.executor.drain();

    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    // One service reachable on two interfaces: two events, no deduplication.
    REQUIRE(found.size() == 2);
    std::vector<std::string> interfaces{found[0].first, found[1].first};
    std::ranges::sort(interfaces);
    REQUIRE(interfaces == std::vector<std::string>{"nic1", "nic2"});
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

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{});

    basic_nic_group<inproc_test_policy, basic_service_monitor> grp{
        f.executor, std::move(grp_opts), std::move(mon_opts)};
    grp.watch("_test._tcp.local.");
    grp.start();
    f.executor.drain();

    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    auto services = grp.services();
    if(mode == dedup_mode::merged)
    {
        // Merged: one entry per instance name across both interfaces.
        REQUIRE(services.size() == 1);
        REQUIRE(services[0].instance_name.str() == "svc._test._tcp.local.");
    }
    else
    {
        // Per-interface: one entry per (instance, interface) pair.
        REQUIRE(services.size() == 2);
        std::vector<std::string> interfaces{
            services[0].source_interface.name, services[1].source_interface.name};
        std::ranges::sort(interfaces);
        REQUIRE(interfaces == std::vector<std::string>{"nic1", "nic2"});
    }

    grp.stop();
}

TEST_CASE("nic_group interface_filter suppresses per-NIC instances", "[nic_group]")
{
    group_fixture f;

    std::vector<std::string> found_interfaces;
    auto grp_opts = f.make_grp_opts();
    grp_opts.interface_filter = [](const network_interface &nic) { return nic.name == "nic1"; };
    grp_opts.on_found = [&](const network_interface &nic, const resolved_service &)
    {
        found_interfaces.push_back(nic.name);
    };

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{});

    basic_nic_group<inproc_test_policy, basic_service_monitor> grp{
        f.executor, std::move(grp_opts), std::move(mon_opts)};
    grp.watch("_test._tcp.local.");
    grp.start();
    f.executor.drain();

    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    REQUIRE(found_interfaces == std::vector<std::string>{"nic1"});

    grp.stop();
}

TEST_CASE("nic_group wires runtime-added NICs to the group-level callbacks", "[nic_group]")
{
    group_fixture f;
    f.nics->pop_back(); // start with nic1 only

    std::vector<std::pair<std::string, std::string>> found;
    auto grp_opts = f.make_grp_opts();
    grp_opts.on_found = [&](const network_interface &nic, const resolved_service &svc)
    {
        found.emplace_back(nic.name, svc.instance_name.str());
    };

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{});

    basic_nic_group<inproc_test_policy, basic_service_monitor> grp{
        f.executor, std::move(grp_opts), std::move(mon_opts)};
    grp.watch("_test._tcp.local.");
    grp.start();
    f.executor.drain();

    // nic2 appears at runtime; the poll picks it up after poll_interval.
    f.nics->push_back(make_nic(2, "nic2", "10.0.1.1"));
    f.advance(std::chrono::milliseconds{100});
    f.executor.drain();

    // A service announced after the NIC addition is discovered on both NICs.
    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    REQUIRE(found.size() == 2);
    std::vector<std::string> interfaces{found[0].first, found[1].first};
    std::ranges::sort(interfaces);
    REQUIRE(interfaces == std::vector<std::string>{"nic1", "nic2"});

    grp.stop();
}

TEST_CASE("nic_group forwards server callbacks to every per-NIC server", "[nic_group]")
{
    group_fixture f;

    std::vector<std::string> query_senders;
    server_peer_options srv_opts;
    srv_opts.info = make_service("svc._test._tcp.local.");
    srv_opts.service.on_query = [&](const endpoint &sender, dns_type, response_mode)
    {
        query_senders.push_back(sender.address);
    };

    std::vector<server_peer_options> srv_opts_vec;
    srv_opts_vec.push_back(std::move(srv_opts));

    basic_nic_group<inproc_test_policy, basic_service_server> grp{
        f.executor, f.make_grp_opts(), std::move(srv_opts_vec)};
    grp.start();
    f.executor.drain();
    f.advance_to_live();

    // A PTR query for the announced type reaches both per-NIC servers; the
    // shared on_query callable fires once per instance.
    basic_querier<inproc_test_policy> querier{f.executor};
    querier.async_query("_test._tcp.local.", dns_type::ptr,
        [](std::error_code, std::vector<mdns_record_variant>) {});
    f.advance(std::chrono::milliseconds{120}); // RFC 6762 random query delay upper bound
    f.executor.drain();

    REQUIRE(query_senders.size() == 2);

    grp.stop();
}

TEST_CASE("nic_group propagates every server_peer_options element per NIC", "[nic_group]")
{
    group_fixture f;
    f.nics->pop_back(); // single NIC: instance count == element count

    std::vector<server_peer_options> srv_opts_vec;
    srv_opts_vec.push_back(server_peer_options{.info = make_service("alpha._test._tcp.local.")});
    srv_opts_vec.push_back(server_peer_options{.info = make_service("beta._test._tcp.local.")});

    basic_nic_group<inproc_test_policy, basic_service_server> grp{
        f.executor, f.make_grp_opts(), std::move(srv_opts_vec)};
    grp.start();
    f.executor.drain();

    // A standalone monitor observes the announcements of both server instances.
    std::vector<std::string> found;
    monitor_options mon_opts;
    mon_opts.on_found = [&](const resolved_service &svc) { found.push_back(svc.instance_name.str()); };
    basic_service_monitor<inproc_test_policy, test_clock> monitor{f.executor, std::move(mon_opts)};
    monitor.watch("_test._tcp.local.");
    monitor.async_start();
    f.executor.drain();

    f.advance_to_live();

    std::ranges::sort(found);
    REQUIRE(found == std::vector<std::string>{"alpha._test._tcp.local.", "beta._test._tcp.local."});

    grp.stop();
}

TEST_CASE("nic_group fires interface-stamped on_record for observer peers", "[nic_group]")
{
    group_fixture f;

    std::vector<std::string> record_interfaces;
    auto grp_opts = f.make_grp_opts();
    grp_opts.on_record = [&](const network_interface &nic, const endpoint &, const mdns_record_variant &)
    {
        if(std::ranges::find(record_interfaces, nic.name) == record_interfaces.end())
            record_interfaces.push_back(nic.name);
    };

    std::vector<observer_options> obs_opts;
    obs_opts.push_back(observer_options{});

    basic_nic_group<inproc_test_policy, basic_observer> grp{
        f.executor, std::move(grp_opts), std::move(obs_opts)};
    grp.start();
    f.executor.drain();

    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    std::ranges::sort(record_interfaces);
    REQUIRE(record_interfaces == std::vector<std::string>{"nic1", "nic2"});

    grp.stop();
}

TEST_CASE("nic_group rejects callback-bearing per-NIC monitor options", "[nic_group]")
{
    group_fixture f;

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{
        .on_found = [](const resolved_service &) {},
    });

    try
    {
        basic_nic_group<inproc_test_policy, basic_service_monitor> grp{
            f.executor, f.make_grp_opts(), std::move(mon_opts)};
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
        basic_nic_group<inproc_test_policy, basic_observer> grp{
            f.executor, f.make_grp_opts(), std::move(obs_opts)};
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

    std::vector<std::string> found_interfaces;
    auto grp_opts = f.make_grp_opts();
    grp_opts.on_found = [&](const network_interface &nic, const resolved_service &)
    {
        found_interfaces.push_back(nic.name);
    };

    std::vector<monitor_options> mon_opts;
    mon_opts.push_back(monitor_options{});

    basic_nic_group<inproc_test_policy, basic_service_monitor> grp{
        f.executor, std::move(grp_opts), std::move(mon_opts)};
    grp.watch("_test._tcp.local.");
    grp.start();
    grp.start(); // no-op: instances must not be duplicated
    f.executor.drain();

    basic_service_server<inproc_test_policy> server{f.executor, make_service("svc._test._tcp.local.")};
    server.async_start();
    f.advance_to_live();

    REQUIRE(found_interfaces.size() == 2); // one event per NIC, not four

    grp.stop();
    grp.stop(); // idempotent

    // Restart creates fresh instances which re-discover the (still live) service.
    found_interfaces.clear();
    grp.start();
    f.executor.drain();
    REQUIRE(grp.services().empty());
    grp.stop();
}

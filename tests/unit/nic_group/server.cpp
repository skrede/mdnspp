#include "fixture.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/observer_options.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <utility>
#include <algorithm>
#include <system_error>

namespace {

std::vector<server_peer_options> server_opts(std::vector<std::string> names)
{
    std::vector<server_peer_options> opts;
    for(auto &name : names)
        opts.push_back(server_peer_options{.info = make_service(std::move(name))});
    return opts;
}

}

TEST_CASE("nic_group forwards server callbacks to every per-NIC server", "[nic_group]")
{
    group_fixture f;
    std::vector<std::string> query_senders;
    auto srv_opts = server_opts({"svc._test._tcp.local."});
    srv_opts[0].service.on_query = [&](const endpoint &sender, dns_type, response_mode)
    {
        query_senders.push_back(sender.address);
    };

    server_group grp{f.executor, f.make_grp_opts(), std::move(srv_opts)};
    grp.start();
    f.executor.drain();
    f.advance_to_live();

    // The PTR query reaches both per-NIC servers; the shared on_query callable fires once per instance.
    basic_querier<inproc_test_policy> querier{f.executor};
    querier.async_query("_test._tcp.local.", dns_type::ptr, [](std::error_code, std::vector<mdns_record_variant>) {});
    f.advance_until([&] { return query_senders.size() >= 2; }, 10ms, 25);

    REQUIRE(query_senders.size() == 2);
    grp.stop();
}

TEST_CASE("nic_group propagates every server_peer_options element per NIC", "[nic_group]")
{
    group_fixture f;
    f.nics->pop_back(); // one instance per element

    server_group grp{f.executor, f.make_grp_opts(), server_opts({"alpha._test._tcp.local.", "beta._test._tcp.local."})};
    grp.start();
    f.executor.drain();

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

    observer_group grp{f.executor, std::move(grp_opts), std::move(obs_opts)};
    grp.start();
    f.executor.drain();
    announced_service svc{f};

    std::ranges::sort(record_interfaces);
    REQUIRE(record_interfaces == std::vector<std::string>{"nic1", "nic2"});
    grp.stop();
}

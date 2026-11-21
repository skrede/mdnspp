#include "fixture.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/basic_querier.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <optional>
#include <string_view>
#include <system_error>

namespace {

service_info make_auto_service(std::string_view instance)
{
    auto info = service_info::make(instance, "_test._tcp", 8080, {.hostname = "host"});
    REQUIRE(info.has_value());
    REQUIRE(info->auto_address);
    return std::move(*info);
}

service_info make_service_on_port(std::string name, uint16_t port)
{
    service_info info = make_service(std::move(name));
    info.port = port;
    return info;
}

// Every conflict gives up (no rename), so a server that sees a conflict never goes live.
struct sibling_watch
{
    sibling_watch()
        : name_conflicts(0)
        , deferrals(0)
        , ptr_answers(0)
    {
    }

    std::vector<server_peer_options> servers(std::vector<service_info> infos, std::chrono::milliseconds probe_bound)
    {
        std::vector<server_peer_options> opts;
        for(auto &info : infos)
            opts.push_back(server(std::move(info), probe_bound));
        return opts;
    }

    server_peer_options server(service_info info, std::chrono::milliseconds probe_bound)
    {
        server_peer_options opts{.info = std::move(info)};
        opts.service.probe_initial_delay_max = probe_bound;
        opts.service.on_conflict = [this](std::string_view, uint32_t, conflict_type type) -> std::optional<std::string>
        {
            ++(type == conflict_type::name_conflict ? name_conflicts : deferrals);
            return std::nullopt;
        };
        opts.service.on_query = [this](const endpoint &, dns_type type, response_mode)
        {
            if(type == dns_type::ptr)
                ++ptr_answers;
        };
        return opts;
    }

    void query(group_fixture &f, int32_t expected)
    {
        ptr_answers = 0;
        basic_querier<inproc_test_policy> querier{f.executor};
        querier.async_query("_test._tcp.local.", dns_type::ptr,
                            [](std::error_code, std::vector<mdns_record_variant>) {});
        f.advance_until([&] { return ptr_answers >= expected; }, 10ms, 25);
    }

    int32_t name_conflicts;
    int32_t deferrals;
    int32_t ptr_answers;
};

void start_live(group_fixture &f, server_group &grp)
{
    grp.start();
    f.executor.drain();
    f.advance_to_live();
}

void add_second_nic_live(group_fixture &f)
{
    f.nics->push_back(make_nic(2, "nic2", "10.0.1.1"));
    f.advance(100ms);
    f.executor.drain();
    f.advance_to_live();
}

void require_all_live(group_fixture &f, sibling_watch &watch, int32_t servers)
{
    watch.query(f, servers);
    REQUIRE(watch.name_conflicts == 0);
    REQUIRE(watch.deferrals == 0);
    REQUIRE(watch.ptr_answers == servers);
}

}

TEST_CASE("nic_group server added for a late NIC goes live beside its live sibling", "[nic_group]")
{
    group_fixture f;
    f.nics->pop_back();
    sibling_watch watch;
    server_group grp{f.executor, f.make_grp_opts(), watch.servers({make_service("svc._test._tcp.local.")}, 250ms)};
    start_live(f, grp);

    add_second_nic_live(f);
    require_all_live(f, watch, 2);
    grp.stop();
}

TEST_CASE("nic_group server with its own address added for a late NIC goes live beside its sibling", "[nic_group]")
{
    group_fixture f;
    f.nics->pop_back();
    sibling_watch watch;
    server_group grp{f.executor, f.make_grp_opts(), watch.servers({make_auto_service("svc")}, 250ms)};
    start_live(f, grp);

    add_second_nic_live(f);
    require_all_live(f, watch, 2);
    grp.stop();
}

TEST_CASE("nic_group servers with their own addresses probing at once go live (probe delay bound 0 ms)", "[nic_group]")
{
    group_fixture f;
    sibling_watch watch;
    server_group grp{f.executor, f.make_grp_opts(), watch.servers({make_auto_service("svc")}, 0ms)};
    start_live(f, grp);

    require_all_live(f, watch, 2);
    grp.stop();
}

TEST_CASE("nic_group services sharing a hostname on one NIC go live (probe delay bound 0 ms)", "[nic_group]")
{
    group_fixture f;
    f.nics->pop_back();
    sibling_watch watch;
    auto opts = watch.servers({make_service_on_port("alpha._test._tcp.local.", 8080),
                               make_service_on_port("beta._test._tcp.local.", 9090)}, 0ms);
    server_group grp{f.executor, f.make_grp_opts(), std::move(opts)};
    start_live(f, grp);

    require_all_live(f, watch, 2);
    grp.stop();
}

TEST_CASE("nic_group services claiming one instance name still conflict (probe delay bound 0 ms)", "[nic_group]")
{
    group_fixture f;
    f.nics->pop_back();
    sibling_watch watch;
    auto opts = watch.servers({make_service_on_port("svc._test._tcp.local.", 8080),
                               make_service_on_port("svc._test._tcp.local.", 9090)}, 0ms);
    server_group grp{f.executor, f.make_grp_opts(), std::move(opts)};
    start_live(f, grp);
    f.advance_to_live();

    REQUIRE(watch.name_conflicts >= 1);
    grp.stop();
}

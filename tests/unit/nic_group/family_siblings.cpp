#include "fixture.h"
#include "sniffer.h"

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/query_options.h"
#include "mdnspp/observer_options.h"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <variant>
#include <optional>
#include <algorithm>
#include <string_view>
#include <system_error>

namespace {

using address_pair = std::pair<std::string, std::string>;

observer_options record_addresses(std::map<std::string, address_pair> &by_sender)
{
    return observer_options{.on_record = [&by_sender](const endpoint &sender, const mdns_record_variant &record)
    {
        if(const auto *a = std::get_if<record_a>(&record))
            by_sender[sender.address].first = a->address_string;
        if(const auto *aaaa = std::get_if<record_aaaa>(&record))
            by_sender[sender.address].second = aaaa->address_string;
    }};
}

// One sender is one server instance; every instance on a group announces its NIC's first A and AAAA.
struct announced_addresses
{
    announced_addresses(group_fixture &f, const char *group)
        : by_sender()
        , observer{f.executor, record_addresses(by_sender), sniffer_options(group)}
    {
        observer.async_observe();
    }

    std::vector<address_pair> pairs() const
    {
        std::vector<address_pair> result;
        for(const auto &[sender, addresses] : by_sender)
            result.push_back(addresses);
        std::ranges::sort(result);
        return result;
    }

    std::map<std::string, address_pair> by_sender;
    basic_observer<inproc_test_policy> observer;
};

struct live_watch
{
    live_watch()
        : conflicts(0)
        , ptr_answers(0)
    {
    }

    std::vector<server_peer_options> server()
    {
        auto info = service_info::make("svc", "_test._tcp", 8080, {.hostname = "host"});
        server_peer_options opts{.info = std::move(*info)};
        opts.service.on_conflict = [this](std::string_view, uint32_t, conflict_type) -> std::optional<std::string>
        {
            ++conflicts;
            return std::nullopt;
        };
        opts.service.on_query = [this](const endpoint &, dns_type type, response_mode)
        {
            ptr_answers += type == dns_type::ptr ? 1 : 0;
        };
        std::vector<server_peer_options> servers;
        servers.push_back(std::move(opts));
        return servers;
    }

    int32_t answers_on(group_fixture &f, const char *group)
    {
        ptr_answers = 0;
        basic_querier<inproc_test_policy> querier{f.executor, query_options{}, sniffer_options(group)};
        querier.async_query("_test._tcp.local.", dns_type::ptr, [](std::error_code, std::vector<mdns_record_variant>) {});
        f.advance_until([this] { return ptr_answers >= 2; }, 10ms, 25);
        return ptr_answers;
    }

    int32_t conflicts;
    int32_t ptr_answers;
};

void use_two_dual_stack_nics(group_fixture &f)
{
    f.nics->clear();
    f.nics->push_back(make_nic(1, "nic1", {"10.0.0.1", "10.0.0.9", "fd00::1", "fd00::9"}));
    f.nics->push_back(make_nic(2, "nic2", {"10.0.1.1", "fd00:1::1", "fe80::2"}));
}

struct dual_stack_run
{
    explicit dual_stack_run(group_fixture &f)
        : traffic{f.executor}
        , ipv4{f, ipv4_group}
        , ipv6{f, ipv6_group}
        , watch{}
        , grp{f.executor, f.make_grp_opts(), watch.server()}
    {
        grp.start();
        f.advance_to_live();
    }

    family_traffic traffic;
    announced_addresses ipv4;
    announced_addresses ipv6;
    live_watch watch;
    server_group grp;
};

}

TEST_CASE("nic_group probes and announces each family of dual-stack NICs on its own group", "[nic_group][family]")
{
    group_fixture f;
    use_two_dual_stack_nics(f);
    dual_stack_run run{f};

    // RFC 6762 section 8.1: each instance sends three probes.
    CHECK(run.traffic.ipv4.queries == 6);
    CHECK(run.traffic.ipv6.queries == 6);
    CHECK(run.traffic.ipv4.responses > 0);
    CHECK(run.traffic.ipv6.responses > 0);
    const std::vector<address_pair> expected{{"10.0.0.1", "fd00::1"}, {"10.0.1.1", "fd00:1::1"}};
    CHECK(run.ipv4.pairs() == expected);
    CHECK(run.ipv6.pairs() == expected);
    run.grp.stop();
}

TEST_CASE("nic_group runs the IPv4 and IPv6 servers of dual-stack NICs live without conflict", "[nic_group][family]")
{
    group_fixture f;
    use_two_dual_stack_nics(f);
    dual_stack_run run{f};

    CHECK(run.watch.answers_on(f, ipv4_group) == 2);
    CHECK(run.watch.answers_on(f, ipv6_group) == 2);
    CHECK(run.watch.conflicts == 0);
    run.grp.stop();
}

#include "fixture.h"
#include "raw_sender.h"

#include "mdnspp/detail/dns_enums.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstdint>
#include <utility>

namespace {

using address_list = std::vector<std::string>;

struct event_log
{
    std::vector<resolved_service> found;
    std::vector<std::pair<resolved_service, dns_type>> updated;
    std::vector<std::pair<resolved_service, loss_reason>> lost;
};

group_options recording(group_fixture &f, event_log &log)
{
    group_options opts = f.make_grp_opts();
    opts.on_found = [&log](const network_interface &, const resolved_service &svc)
    {
        log.found.push_back(svc);
    };
    opts.on_updated = [&log](const network_interface &, const resolved_service &svc, update_event, dns_type type)
    {
        log.updated.emplace_back(svc, type);
    };
    opts.on_lost = [&log](const network_interface &, const resolved_service &svc, loss_reason reason)
    {
        log.lost.emplace_back(svc, reason);
    };
    return opts;
}

const raw_service both_addresses{.ipv4 = "192.0.2.10", .ipv6 = "2001:db8::10"};

struct dual_stack_fixture : group_fixture
{
    dual_stack_fixture()
    {
        nics->clear();
        nics->push_back(make_nic(1, "nic1", {"10.0.0.1", "fd00::1"}));
    }
};

struct dual_stack_watch
{
    explicit dual_stack_watch(const raw_service &on_ipv6)
        : f()
        , log()
        , senders{f.executor}
        , grp{f.executor, recording(f, log), one_monitor()}
    {
        f.start_watching(grp);
        senders.ipv4.send(both_addresses);
        senders.ipv6.send(on_ipv6);
        f.advance(200ms);
    }

    ~dual_stack_watch() { grp.stop(); }

    const resolved_service &latest() const
    {
        return log.updated.empty() ? log.found.back() : log.updated.back().first;
    }

    void say_goodbye(group_sender &sender)
    {
        raw_service goodbye = both_addresses;
        goodbye.srv_ttl = 0s;
        sender.send(goodbye, dns_type::srv);
        f.executor.drain();
        for(int32_t i = 0; i < 10; ++i)
            f.advance(1s);
    }

    dual_stack_fixture f;
    event_log log;
    family_senders senders;
    monitor_group grp;
};

}

TEST_CASE("nic_group fires on_found once per NIC across families", "[nic_group][family]")
{
    dual_stack_watch w{both_addresses};

    REQUIRE(w.log.found.size() == 1);
    CHECK(w.latest().ipv4_addresses == address_list{"192.0.2.10"});
    CHECK(w.latest().ipv6_addresses == address_list{"2001:db8::10"});
}

TEST_CASE("nic_group fires on_lost once the last family lost the service", "[nic_group][family]")
{
    dual_stack_watch w{both_addresses};
    w.log = event_log{};

    w.say_goodbye(w.senders.ipv4);
    CHECK(w.log.lost.empty());
    CHECK(w.log.updated.empty());

    w.say_goodbye(w.senders.ipv6);
    REQUIRE(w.log.lost.size() == 1);
    CHECK(w.log.lost[0].second == loss_reason::goodbye);
    CHECK(w.log.updated.empty());
}

TEST_CASE("nic_group fires on_updated with the united service when one family changes it", "[nic_group][family]")
{
    dual_stack_watch w{{.ipv6 = "2001:db8::10"}};
    w.log = event_log{};

    w.senders.ipv6.send({.ipv6 = "2001:db8::11"}, dns_type::aaaa);
    w.f.executor.drain();

    REQUIRE(w.log.updated.size() == 1);
    CHECK(w.log.updated[0].second == dns_type::aaaa);
    CHECK(w.log.updated[0].first.ipv4_addresses == address_list{"192.0.2.10"});
    CHECK(w.log.updated[0].first.ipv6_addresses == address_list{"2001:db8::10", "2001:db8::11"});
}

TEST_CASE("nic_group stays silent when a family update leaves the united service equal", "[nic_group][family]")
{
    dual_stack_watch w{{.ipv6 = "2001:db8::10"}};
    w.log = event_log{};

    w.senders.ipv6.send({.ipv4 = "192.0.2.10"}, dns_type::a);
    w.f.executor.drain();

    CHECK(w.log.found.empty());
    CHECK(w.log.updated.empty());
}

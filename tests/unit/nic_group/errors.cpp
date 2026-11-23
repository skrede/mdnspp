#include "fixture.h"
#include "sniffer.h"
#include "failing_socket.h"

#include "support/failure_injection.h"

#include "mdnspp/records.h"
#include "mdnspp/basic_querier.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <string_view>
#include <system_error>

namespace {

struct reported_error
{
    std::string nic;
    std::error_code ec;
    std::string context;

    bool operator==(const reported_error &) const = default;
};

template <typename Options>
Options record_errors(Options opts, std::vector<reported_error> &errors)
{
    opts.on_error = [&errors](const network_interface &nic, std::error_code ec, std::string_view context)
    {
        errors.push_back({nic.name, ec, std::string(context)});
    };
    return opts;
}

basic_nic_group_options<failing_policy> failing_options(group_fixture &f, std::vector<reported_error> &errors)
{
    basic_nic_group_options<failing_policy> opts;
    opts.monitor_opts = f.make_grp_opts().monitor_opts;
    return record_errors(std::move(opts), errors);
}

std::vector<reported_error> construction_errors(std::string_view peer)
{
    const auto ec = std::make_error_code(std::errc::address_not_available);
    const std::string context = std::string(peer) + " construction";
    return {{"nic1", ec, context}, {"nic2", ec, context}};
}

template <typename Group, typename PeerOptions>
std::vector<reported_error> start_failing(group_fixture &f, PeerOptions peer_opts)
{
    std::vector<reported_error> errors;
    Group grp{f.executor, failing_options(f, errors), std::move(peer_opts)};
    test_support::failure_injection guard{true, false};
    CHECK_NOTHROW(grp.start());
    grp.stop();
    return errors;
}

}

TEST_CASE("nic_group reports a server construction failure per NIC and stays usable", "[nic_group][errors]")
{
    group_fixture f;
    family_traffic traffic{f.executor};
    std::vector<reported_error> errors;
    basic_nic_group<failing_policy, basic_service_server> grp{f.executor, failing_options(f, errors), one_server()};
    {
        test_support::failure_injection guard{true, false};
        REQUIRE_NOTHROW(grp.start());
    }
    CHECK(errors == construction_errors("service_server"));

    f.nics->push_back(make_nic(3, "nic3", "10.0.2.1"));
    f.advance(100ms);
    f.advance_to_live();
    CHECK(errors.size() == 2);
    CHECK(traffic.ipv4.queries > 0);
    grp.stop();
}

TEST_CASE("nic_group reports monitor and observer construction failures per NIC", "[nic_group][errors]")
{
    group_fixture f;
    CHECK(start_failing<basic_nic_group<failing_policy, basic_service_monitor>>(f, one_monitor()) ==
          construction_errors("service_monitor"));
    CHECK(start_failing<basic_nic_group<failing_policy, basic_observer>>(f, std::vector<observer_options>(1)) ==
          construction_errors("observer"));
}

TEST_CASE("nic_group skips a family whose factory options name the other family", "[nic_group][errors]")
{
    group_fixture f;
    f.nics->clear();
    f.nics->push_back(make_nic(1, "nic1", {"10.0.0.1", "fd00::1"}));
    family_traffic traffic{f.executor};
    std::vector<reported_error> errors;
    auto grp_opts = f.make_grp_opts();
    grp_opts.socket_options_factory = [](const network_interface &, address_family)
    {
        return inproc::inproc_socket_options{};
    };
    server_group grp{f.executor, record_errors(std::move(grp_opts), errors), one_server()};
    grp.start();
    f.advance_to_live();

    CHECK(errors == std::vector<reported_error>{{"nic1", std::make_error_code(std::errc::invalid_argument),
                                                 "socket_options_factory"}});
    // RFC 6762 section 8.1: one server instance sends three probes.
    CHECK(traffic.ipv4.queries == 3);
    CHECK(traffic.ipv6.queries == 0);
    grp.stop();
}

TEST_CASE("nic_group servers answer after the group's response delay", "[nic_group][options]")
{
    group_fixture f;
    f.nics->pop_back();
    family_traffic traffic{f.executor};
    auto grp_opts = f.make_grp_opts();
    grp_opts.mdns_opts.response_delay_min = 1000ms;
    grp_opts.mdns_opts.response_delay_max = 1000ms;
    server_group grp{f.executor, std::move(grp_opts), one_server()};
    grp.start();
    f.advance_to_live();
    const int32_t probes = traffic.ipv4.queries;
    const int32_t announcements = traffic.ipv4.responses;

    basic_querier<inproc_test_policy> querier{f.executor};
    querier.async_query("_test._tcp.local.", dns_type::ptr, [](std::error_code, std::vector<mdns_record_variant>) {});
    f.advance_until([&] { return traffic.ipv4.queries > probes; }, 10ms, 20);
    f.advance(500ms);
    CHECK(traffic.ipv4.responses == announcements);
    f.advance(600ms);
    CHECK(traffic.ipv4.responses > announcements);
    grp.stop();
}

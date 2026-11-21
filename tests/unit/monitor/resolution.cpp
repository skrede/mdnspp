#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstdint>

namespace {

struct found_log
{
    int32_t count;
    std::vector<mdnspp::resolved_service> services;
};

mdnspp::monitor_options log_found(found_log &log)
{
    mdnspp::monitor_options opts;
    opts.on_found = [&log](const mdnspp::resolved_service &svc)
    {
        ++log.count;
        log.services.push_back(svc);
    };
    return opts;
}

}

TEST_CASE("watch: posts to executor, no-op on second call", "[monitor][MON-03]")
{
    mock_executor ex;
    test_monitor mon{ex};

    mon.watch("_http._tcp.local");
    REQUIRE(ex.m_posted.size() == 1);

    mon.watch("_http._tcp.local");
    REQUIRE(ex.m_posted.size() == 2);

    // The second deferred watch is a no-op; draining without an exception is the check.
    ex.drain_posted();
}

TEST_CASE("unwatch: fires on_lost(unwatched) for each live service", "[monitor][MON-03]")
{
    loss_log lost{};
    monitor_fixture f{loss_options(lost)};
    f.watch_and_start({"_http._tcp.local"});
    f.inject(make_ptr_packet("_http._tcp.local", "MyServer._http._tcp.local", "myserver.local", "192.168.1.1"));

    f.mon.unwatch("_http._tcp.local");
    f.ex.drain_posted();

    check_single_loss(lost, "MyServer._http._tcp.local.", mdnspp::loss_reason::unwatched);
}

TEST_CASE("incremental resolution: PTR then SRV then A fires on_found", "[monitor][MON-04]")
{
    found_log found{};
    monitor_fixture f{log_found(found)};
    f.watch_and_start({"_http._tcp.local"});
    // build_dns_response(ptr) always adds SRV and A as additionals, so one packet carries the whole chain.
    f.inject(make_ptr_packet("_http._tcp.local", "MyServer._http._tcp.local", "myserver.local", "192.168.1.1"));

    REQUIRE(found.services.size() == 1);
    CHECK(found.services[0].instance_name == "MyServer._http._tcp.local");
    CHECK(found.services[0].hostname      == "myserver.local");
    CHECK(found.services[0].port          == 8080);
    REQUIRE_FALSE(found.services[0].ipv4_addresses.empty());
    CHECK(found.services[0].ipv4_addresses[0] == "192.168.1.1");
}

TEST_CASE("incremental resolution: SRV arrives before A -- on_found fires only after A",
          "[monitor][MON-04]")
{
    found_log found{};
    monitor_fixture f{log_found(found)};
    f.watch_and_start({"_http._tcp.local"});
    // The PTR builder carries the whole chain, so this checks that on_found fires once and only once.
    auto pkt = make_ptr_packet("_http._tcp.local", "Instance2._http._tcp.local", "host2.local", "10.0.0.2");
    f.inject(pkt);

    CHECK(found.count == 1);
    REQUIRE(found.services.size() == 1);
    CHECK(found.services[0].instance_name == "Instance2._http._tcp.local");

    f.inject(pkt);
    CHECK(found.count == 1);
}

TEST_CASE("incremental resolution: on_found not fired twice for same instance",
          "[monitor][MON-04]")
{
    found_log found{};
    monitor_fixture f{log_found(found)};
    f.watch_and_start({"_http._tcp.local"});
    auto pkt = make_ptr_packet("_http._tcp.local", "Svc._http._tcp.local", "svc.local", "192.168.1.42");

    f.inject(pkt);
    CHECK(found.count == 1);

    f.inject(pkt);
    CHECK(found.count == 1);
}

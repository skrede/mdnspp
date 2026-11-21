#include "inproc_bus/helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace {

mdns_options short_backoff_opts()
{
    mdns_options opts;
    opts.initial_interval = 200ms;
    opts.max_interval = 400ms;
    return opts;
}

void check_found(const service_events &events, std::string_view instance, uint16_t port)
{
    REQUIRE_FALSE(events.found.empty());
    CHECK(events.found[0].instance_name.str() == instance);
    CHECK(events.found[0].port == port);
}

void check_none_named(const service_events &events, std::string_view fragment)
{
    for(const auto &svc : events.found)
        CHECK(svc.instance_name.str().find(fragment) == std::string::npos);
}

void check_routed_by_type(const service_events &http, const service_events &ssh)
{
    check_found(http, "WebServer._http._tcp.local.", 80);
    check_found(ssh, "SSHServer._ssh._tcp.local.", 22);
    check_none_named(http, "ssh");
    check_none_named(ssh, "web");
    CHECK(http.lost.empty());
    CHECK(ssh.lost.empty());
}

void check_ceremony_records(inproc_harness &h, const std::vector<mdns_record_variant> &captured)
{
    // The first probe carries the SRV record in its authority section.
    h.advance(250ms);
    std::size_t after_probe1 = captured.size();
    CHECK(after_probe1 >= 1u);
    finish_ceremony(h);
    CHECK(captured.size() > after_probe1);
    CHECK(holds_record<record_ptr>(captured));
    CHECK(holds_record<record_srv>(captured));
    CHECK(holds_record<record_a>(captured));
}

}

TEST_CASE("Observer captures all traffic", "[inproc][routing]")
{
    inproc_harness h;
    std::vector<mdns_record_variant> captured;
    live_observer obs{h, record_sink(captured)};
    auto server = h.make_server(make_service("ObservedServer._http._tcp.local.", "_http._tcp.local.",
                                             "observed.local.", 9000));
    server.async_start();
    check_ceremony_records(h, captured);

    std::size_t query_response_count = 0;
    live_observer obs2{h, record_counter(query_response_count)};
    live_monitor monitor{h, "_http._tcp.local.", discover_opts(), short_backoff_opts()};
    h.advance(300ms);
    h.advance(300ms);
    // At least the three probe SRV records and PTR, SRV, TXT and A of both announcements.
    CHECK(captured.size() >= 8u);
    obs.observer.stop();
    obs2.observer.stop();
    h.executor.drain();
}

TEST_CASE("Multiple services and types routing", "[inproc][routing]")
{
    inproc_harness h;
    auto server_a = h.make_server(make_service("WebServer._http._tcp.local.", "_http._tcp.local.", "webserver.local.",
                                               80, "192.168.1.10"));
    auto server_b = h.make_server(make_service("SSHServer._ssh._tcp.local.", "_ssh._tcp.local.", "sshserver.local.",
                                               22, "192.168.1.20"));
    server_a.async_start();
    server_b.async_start();
    // advance_to_live steps the shared clock, so both servers go live together.
    h.advance_to_live(server_a);
    h.executor.drain();

    service_events http;
    service_events ssh;
    live_monitor monitor_a{h, "_http._tcp.local.", http.options(), fast_scheduler_opts()};
    live_monitor monitor_b{h, "_ssh._tcp.local.", ssh.options(), fast_scheduler_opts()};
    // The first step sends the monitors' queries, the second fires the servers' 20-120 ms response timers.
    h.advance(200ms);
    h.advance(200ms);

    check_routed_by_type(http, ssh);
}

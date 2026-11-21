#include "inproc_bus/helpers.h"

#include <catch2/catch_test_macros.hpp>

namespace {

cache_options short_grace()
{
    cache_options copts;
    copts.goodbye_grace = 1s;
    return copts;
}

}

TEST_CASE("Discovery lifecycle: found and lost", "[inproc][discovery]")
{
    inproc_harness h;
    auto server = h.make_server(make_service("MyServer._http._tcp.local.", "_http._tcp.local.", "myserver.local.", 8080));
    server.async_start();
    service_events events;
    live_monitor monitor{h, "_http._tcp.local.", events.options(), fast_scheduler_opts(), short_grace()};
    h.advance_to_live(server);
    h.executor.drain();

    REQUIRE_FALSE(events.found.empty());
    CHECK(events.found[0].instance_name.str() == "MyServer._http._tcp.local.");
    CHECK(events.found[0].port == 8080);
    CHECK_FALSE(events.found[0].ipv4_addresses.empty());

    // The goodbye keeps the SRV record cached for goodbye_grace; on_lost fires on the first scheduler tick after it.
    server.stop();
    h.executor.drain();
    CHECK(events.lost.empty());
    h.advance(200ms);
    CHECK(events.lost.empty());
    h.advance(900ms);

    REQUIRE_FALSE(events.lost.empty());
    CHECK(events.reasons[0] == loss_reason::goodbye);
}

TEST_CASE("Goodbye with delayed expiry", "[inproc][discovery]")
{
    inproc_harness h;
    live_server srv{h, make_service("DelayedBye._http._tcp.local.", "_http._tcp.local.", "delayed.local.", 7070)};
    service_events events;
    live_monitor monitor{h, "_http._tcp.local.", events.options(), fast_scheduler_opts(), short_grace()};
    // The first step sends the monitor's query, the second fires the server's 20-120 ms response timer.
    h.advance(200ms);
    h.advance(200ms);
    REQUIRE_FALSE(events.found.empty());

    srv.server.stop();
    h.executor.drain();
    CHECK(events.lost.empty());
    h.advance(500ms);
    CHECK(events.lost.empty());
    h.advance(600ms);
    CHECK_FALSE(events.lost.empty());
}

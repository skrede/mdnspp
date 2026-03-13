// tests/local_bus_discovery_test.cpp
//
// Multi-party mDNS integration tests using the deterministic local bus.
// All tests use local_harness (shared executor + bus) and test_clock for
// zero-wall-clock-time deterministic timing.
//
// TEST-01: Probe conflict resolution between two servers with the same name.
// TEST-02: Discovery lifecycle (server announces -> monitor discovers -> server stops -> on_lost).
// TEST-10: Goodbye with delayed expiry (on_lost does NOT fire before grace period elapses).

#include "mdnspp/local/local_harness.h"

#include "mdnspp/service_info.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstdint>
#include <optional>

using namespace mdnspp;
using mdnspp::local::local_harness;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

namespace {

service_info make_service(std::string_view name,
                          std::string_view type,
                          std::string_view host,
                          uint16_t port,
                          std::string_view ipv4 = "192.168.1.1")
{
    service_info info;
    info.service_name = std::string(name);
    info.service_type = std::string(type);
    info.hostname     = std::string(host);
    info.port         = port;
    info.address_ipv4 = std::string(ipv4);
    return info;
}

// Build mdns_options with a short scheduler interval for deterministic test timing.
// The default initial_interval of 1s and max_interval of 1h cause the scheduler to
// fire too infrequently for the test's time window. Capping both at 200ms ensures
// erase_expired() is called at least every 200ms, well within any test advance window.
mdns_options fast_scheduler_opts()
{
    mdns_options opts;
    opts.initial_interval = std::chrono::milliseconds{200};
    opts.max_interval     = std::chrono::milliseconds{200};
    return opts;
}

} // namespace

// ---------------------------------------------------------------------------
// TEST-01: Probe conflict resolution between two servers
// ---------------------------------------------------------------------------

TEST_CASE("Probe conflict resolution between two servers", "[local][discovery]")
{
    local_harness h;

    // Both servers claim the same service name but different ports.
    // Their probes are visible to each other via the shared bus.
    // The RFC 6762 section 8.2 tiebreak compares SRV rdata lexicographically;
    // the loser defers and re-probes. At minimum, one server must receive a
    // conflict callback.

    bool conflict_a = false;
    bool conflict_b = false;

    service_options opts_a;
    opts_a.on_conflict = [&](const std::string &, std::string &new_name,
                              unsigned, conflict_type) -> bool
    {
        conflict_a = true;
        new_name   = "SharedName-2._http._tcp.local.";
        return true; // rename and re-probe
    };

    service_options opts_b;
    opts_b.on_conflict = [&](const std::string &, std::string &new_name,
                              unsigned, conflict_type) -> bool
    {
        conflict_b = true;
        new_name   = "SharedName-3._http._tcp.local.";
        return true; // rename and re-probe
    };

    // Same service name, different ports (different SRV rdata => deterministic tiebreak)
    auto server_a = h.make_server(
        make_service("SharedName._http._tcp.local.", "_http._tcp.local.",
                     "host-a.local.", 8080),
        std::move(opts_a));

    auto server_b = h.make_server(
        make_service("SharedName._http._tcp.local.", "_http._tcp.local.",
                     "host-b.local.", 9090),
        std::move(opts_b));

    server_a.async_start();
    server_b.async_start();

    // Drive through the probe+announce ceremony.
    // Both servers share the bus — their probes cross-deliver and trigger tiebreaking.
    // Drive well beyond the default probe window to allow re-probe after defer.
    // Default probe_defer_delay = 1000ms; give 5000ms headroom (20 * 250ms).
    for(int i = 0; i < 20; ++i)
        h.advance(std::chrono::milliseconds{250});

    // At least one server must have received a conflict callback.
    CHECK((conflict_a || conflict_b));
}

// ---------------------------------------------------------------------------
// TEST-02: Discovery lifecycle: found -> lost
// ---------------------------------------------------------------------------

TEST_CASE("Discovery lifecycle: found and lost", "[local][discovery]")
{
    local_harness h;

    // --- Server setup ---
    auto server = h.make_server(
        make_service("MyServer._http._tcp.local.", "_http._tcp.local.",
                     "myserver.local.", 8080));

    server.async_start();

    // --- Monitor setup ---
    // Use a short initial_interval (100ms) so the scheduler fires frequently.
    // This ensures erase_expired() is called within the test's time window,
    // which is necessary to trigger on_lost after the goodbye grace period.
    std::vector<resolved_service> found_services;
    std::vector<resolved_service> lost_services;
    std::vector<loss_reason>      lost_reasons;

    monitor_options mon_opts;
    mon_opts.mode     = monitor_mode::discover;
    mon_opts.on_found = [&](const resolved_service &svc) { found_services.push_back(svc); };
    mon_opts.on_lost  = [&](const resolved_service &svc, loss_reason reason)
    {
        lost_services.push_back(svc);
        lost_reasons.push_back(reason);
    };

    // Short goodbye grace (1s) and short scheduler interval (100ms).
    cache_options copts;
    copts.goodbye_grace = std::chrono::seconds{1};

    auto monitor = h.make_monitor(std::move(mon_opts), {}, fast_scheduler_opts(), std::move(copts));
    monitor.watch("_http._tcp.local.");
    monitor.async_start();
    h.executor.drain();

    // Advance the server through probe + announce.
    // Announcements travel through the bus to the monitor.
    h.advance_to_live(server);
    h.executor.drain();

    // DNS names are lowercased on the wire — instance_name.str() is lowercase.
    REQUIRE_FALSE(found_services.empty());
    CHECK(found_services[0].instance_name.str() == "myserver._http._tcp.local.");
    CHECK(found_services[0].port == 8080);
    CHECK_FALSE(found_services[0].ipv4_addresses.empty());

    // --- Goodbye ---
    // stop() sends a goodbye (TTL=0). The cache retains the SRV record for
    // goodbye_grace (1s) before expiry. on_lost fires on the next scheduler tick
    // after expiry.
    server.stop();
    h.executor.drain();

    // Grace period not elapsed yet — on_lost should not have fired.
    CHECK(lost_services.empty());

    // Advance past the grace period.
    // With initial_interval=100ms, the scheduler fires every 100-200ms.
    // After 1100ms the goodbye SRV record (inserted_at + 1s) is expired,
    // and the next scheduler tick calls erase_expired() and fires on_lost.
    h.advance(std::chrono::milliseconds{200});
    CHECK(lost_services.empty());

    h.advance(std::chrono::milliseconds{900});

    REQUIRE_FALSE(lost_services.empty());
    CHECK(lost_reasons[0] == loss_reason::goodbye);
}

// ---------------------------------------------------------------------------
// TEST-10: Goodbye with delayed expiry
// ---------------------------------------------------------------------------

TEST_CASE("Goodbye with delayed expiry", "[local][discovery]")
{
    local_harness h;

    // --- Server ---
    auto server = h.make_server(
        make_service("DelayedBye._http._tcp.local.", "_http._tcp.local.",
                     "delayed.local.", 7070));

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    // --- Monitor ---
    std::vector<resolved_service> found_services;
    bool lost_fired = false;

    monitor_options mon_opts;
    mon_opts.mode     = monitor_mode::discover;
    mon_opts.on_found = [&](const resolved_service &svc) { found_services.push_back(svc); };
    mon_opts.on_lost  = [&](const resolved_service &, loss_reason) { lost_fired = true; };

    cache_options copts;
    copts.goodbye_grace = std::chrono::seconds{1};

    auto monitor = h.make_monitor(std::move(mon_opts), {}, fast_scheduler_opts(), std::move(copts));
    monitor.watch("_http._tcp.local.");
    monitor.async_start();
    h.executor.drain();

    // Advance to trigger discovery (scheduler fires at 200ms, sends query, server responds).
    h.advance(std::chrono::milliseconds{400});

    REQUIRE_FALSE(found_services.empty());

    // --- Send goodbye ---
    server.stop();
    h.executor.drain();

    // Immediately after goodbye: on_lost must NOT have fired yet.
    CHECK_FALSE(lost_fired);

    // Advance by less than the grace period (500ms < 1000ms grace).
    // The scheduler fires (100ms interval) but erase_expired() won't find the
    // SRV record expired yet — it was inserted at current clock, expires in 1s.
    h.advance(std::chrono::milliseconds{500});
    CHECK_FALSE(lost_fired);

    // Advance past the remainder of the grace period (600ms more = 1100ms total past goodbye).
    h.advance(std::chrono::milliseconds{600});

    CHECK(lost_fired);
}

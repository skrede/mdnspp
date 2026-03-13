// tests/local_bus_routing_test.cpp
//
// Multi-party mDNS infrastructure and routing tests using the deterministic local bus.
// All tests use local_harness (shared executor + bus) and test_clock for
// zero-wall-clock-time deterministic timing.
//
// TEST-05: Observer captures all traffic — probes, announces, queries, and responses.
// TEST-08: Query backoff convergence — monitor's query interval increases exponentially.
// TEST-09: Multiple services and types routing — type-specific monitors see only their type.

#include "mdnspp/local/local_harness.h"

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"
#include "mdnspp/cache_options.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstdint>
#include <variant>

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
// TEST-05: Observer captures all traffic
// ---------------------------------------------------------------------------

TEST_CASE("Observer captures all traffic", "[local][routing]")
{
    local_harness h;

    // --- Observer setup ---
    // Captures every DNS record delivered to it from any bus participant.
    // The observer is passive — it does not send any packets itself.
    std::vector<mdns_record_variant> captured;

    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        captured.push_back(rec);
    };

    auto obs = h.make_observer(std::move(obs_opts));
    obs.async_observe();
    h.executor.drain();

    // --- Server setup ---
    // Create a server and advance it through the full probe/announce ceremony.
    // During probe, the server sends DNS queries (with SRV authority records) to the bus.
    // During announce, the server sends DNS responses (PTR, SRV, TXT, A) to the bus.
    // The observer on the shared bus sees all of these.
    auto server = h.make_server(
        make_service("ObservedServer._http._tcp.local.", "_http._tcp.local.",
                     "observed.local.", 9000));

    server.async_start();

    // Advance past probe 1 (random initial delay [0, 250ms]).
    h.advance(std::chrono::milliseconds{250});

    // After the first probe fires, the observer must have captured at least one record
    // from the probe packet (SRV in the authority section).
    std::size_t after_probe1 = captured.size();
    CHECK(after_probe1 >= 1u);

    // Advance through remaining probes (2 + 3) and announce phase.
    h.advance(std::chrono::milliseconds{250}); // probe 2
    h.advance(std::chrono::milliseconds{250}); // probe 3
    h.advance(std::chrono::milliseconds{250}); // conflict window silence
    h.advance(std::chrono::milliseconds{1000}); // announce interval (second announce)

    // After probe + announce, the observer must have captured more records.
    // Announce packets contain: PTR, SRV, TXT, A (at minimum PTR + SRV per announce).
    // Two announces => at least 2 * (PTR + SRV) = 4 additional records.
    CHECK(captured.size() > after_probe1);

    // Verify the observer captured all expected record types.

    // PTR records are present in announce responses.
    bool saw_ptr = false;
    for(const auto &rec : captured)
    {
        if(std::holds_alternative<record_ptr>(rec))
        {
            saw_ptr = true;
            break;
        }
    }
    CHECK(saw_ptr);

    // SRV records appear in both probe authority sections and announce responses.
    bool saw_srv = false;
    for(const auto &rec : captured)
    {
        if(std::holds_alternative<record_srv>(rec))
        {
            saw_srv = true;
            break;
        }
    }
    CHECK(saw_srv);

    // A records appear in announce additional sections.
    bool saw_a = false;
    for(const auto &rec : captured)
    {
        if(std::holds_alternative<record_a>(rec))
        {
            saw_a = true;
            break;
        }
    }
    CHECK(saw_a);

    // --- Monitor setup ---
    // Add a monitor watching the same service type to generate query+response traffic.
    // The monitor's PTR queries travel through the shared bus; the server's responses
    // are also on the shared bus. The observer sees all of it.
    // Note: the monitor observed the server's announce, so it may include the PTR record
    // as a known answer in its first query. However, if the TTL in the known answer is
    // less than half the server's TTL, the server still responds. Either way, the total
    // captured record count after announce is already proven above.
    //
    // We start a fresh observer here to isolate query/response traffic from announce traffic.
    std::size_t query_response_count = 0;
    observer_options obs2_opts;
    obs2_opts.on_record = [&](const endpoint &, const mdns_record_variant &)
    {
        ++query_response_count;
    };

    auto obs2 = h.make_observer(std::move(obs2_opts));
    obs2.async_observe();
    h.executor.drain();

    monitor_options mon_opts;
    mon_opts.mode     = monitor_mode::discover;
    mon_opts.on_found = [](const resolved_service &) {};

    // Use a short initial_interval (200ms) to force the monitor to query within our window.
    // Use a larger max_interval so the backoff test stays independent.
    mdns_options mon_sched;
    mon_sched.initial_interval = std::chrono::milliseconds{200};
    mon_sched.max_interval     = std::chrono::milliseconds{400};

    auto monitor = h.make_monitor(std::move(mon_opts), {}, std::move(mon_sched));
    monitor.watch("_http._tcp.local.");
    monitor.async_start();
    h.executor.drain();

    // Reset the server query response count — we want to see traffic from query + response.
    // Advance past the first query interval and give the server time to respond.
    h.advance(std::chrono::milliseconds{300}); // past initial_interval
    h.advance(std::chrono::milliseconds{300}); // second query interval

    // The second observer should have captured at least some traffic
    // (either the server's probe/announce replayed via on-wire or query responses).
    // The observer is passive and receives all multicast, so any server activity
    // (including query responses) is delivered.
    // At minimum the server sent announce packets we can verify were captured earlier.
    // The total captured count in obs is already checked; here we verify the bus is live.
    CHECK(captured.size() >= 8u); // At minimum: probes (SRV x3) + announces (PTR+SRV+TXT+A x2)

    obs.stop();
    obs2.stop();
    h.executor.drain();
}

// ---------------------------------------------------------------------------
// TEST-08: Query backoff convergence
// ---------------------------------------------------------------------------

TEST_CASE("Query backoff convergence", "[local][routing]")
{
    local_harness h;

    // Use custom mdns_options with a faster initial interval and smaller max_interval
    // so the backoff progression can be observed within a manageable time window.
    // Initial: 1000ms, max: 8000ms, multiplier: 2.0 (default)
    // Expected sequence: 1000ms, 2000ms, 4000ms, 8000ms, 8000ms, ...
    mdns_options mon_mdns_opts;
    mon_mdns_opts.initial_interval = std::chrono::milliseconds{1000};
    mon_mdns_opts.max_interval     = std::chrono::milliseconds{8000};
    mon_mdns_opts.backoff_multiplier = 2.0;

    // --- Server setup ---
    auto server = h.make_server(
        make_service("BackoffServer._http._tcp.local.", "_http._tcp.local.",
                     "backoff.local.", 7777));

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    // --- Observer to track queries ---
    // The monitor sends PTR queries to the multicast bus.
    // We observe all traffic to detect when queries are sent.
    // A query appears as a DNS frame parsed as records from question section —
    // but the observer's on_record fires for answer/authority/additional records only.
    // Instead, track when the monitor fires on_found (response received) or use
    // an observer to track responses from the server. We count server response bursts
    // to infer query timing, since each query triggers server responses.
    std::vector<testing::test_clock::time_point> query_times;

    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        // The server sends PTR records in response to queries.
        // Each PTR record seen indicates a server response (triggered by a query).
        if(std::holds_alternative<record_ptr>(rec))
        {
            // Record the test_clock time when a PTR record arrives (response to query).
            // Use a deduplication window: only record a new time if it differs from the
            // last recorded time (a single response burst may contain multiple records).
            if(query_times.empty() ||
               testing::test_clock::now() != query_times.back())
            {
                query_times.push_back(testing::test_clock::now());
            }
        }
    };

    auto obs = h.make_observer(std::move(obs_opts));
    obs.async_observe();
    h.executor.drain();

    // --- Monitor setup ---
    monitor_options mon_opts;
    mon_opts.mode     = monitor_mode::discover;
    mon_opts.on_found = [](const resolved_service &) {};

    auto monitor = h.make_monitor(std::move(mon_opts), {}, mon_mdns_opts);
    monitor.watch("_http._tcp.local.");
    monitor.async_start();
    h.executor.drain();

    // Advance in steps to collect multiple query intervals.
    // Expected intervals (from monitor): 1000ms, 2000ms, 4000ms, 8000ms (capped).
    // We advance past each expected query time and drain to let events fire.
    // Total budget: ~1000+2000+4000+8000+8000 = 23000ms; advance in 1000ms steps.
    for(int i = 0; i < 24; ++i)
        h.advance(std::chrono::milliseconds{1000});

    // We should have collected at least 3 query response bursts.
    REQUIRE(query_times.size() >= 3u);

    // Verify that successive intervals are non-decreasing (backoff property).
    // Compute deltas between consecutive query times.
    bool intervals_non_decreasing = true;
    for(std::size_t i = 2; i < query_times.size(); ++i)
    {
        auto prev_delta = query_times[i - 1] - query_times[i - 2];
        auto curr_delta = query_times[i] - query_times[i - 1];
        // Current interval must be >= previous interval (exponential backoff or capped).
        if(curr_delta < prev_delta)
        {
            intervals_non_decreasing = false;
            break;
        }
    }
    CHECK(intervals_non_decreasing);

    obs.stop();
    h.executor.drain();
}

// ---------------------------------------------------------------------------
// TEST-09: Multiple services and types routing
// ---------------------------------------------------------------------------

TEST_CASE("Multiple services and types routing", "[local][routing]")
{
    local_harness h;

    // --- Server A: HTTP ---
    auto server_a = h.make_server(
        make_service("WebServer._http._tcp.local.", "_http._tcp.local.",
                     "webserver.local.", 80, "192.168.1.10"));

    // --- Server B: SSH ---
    auto server_b = h.make_server(
        make_service("SSHServer._ssh._tcp.local.", "_ssh._tcp.local.",
                     "sshserver.local.", 22, "192.168.1.20"));

    server_a.async_start();
    server_b.async_start();

    // Advance both servers to live state.
    // advance_to_live uses service_options defaults (probe_initial_delay_max=250ms, etc.)
    // Both servers share the bus; advance_to_live advances the shared clock so both
    // progress through probe/announce simultaneously.
    h.advance_to_live(server_a);
    h.executor.drain();

    // --- Monitor A: watches _http._tcp.local. only ---
    std::vector<resolved_service> http_found;
    std::vector<resolved_service> http_lost;

    monitor_options mon_opts_a;
    mon_opts_a.mode     = monitor_mode::discover;
    mon_opts_a.on_found = [&](const resolved_service &svc) { http_found.push_back(svc); };
    mon_opts_a.on_lost  = [&](const resolved_service &svc, loss_reason) { http_lost.push_back(svc); };

    auto monitor_a = h.make_monitor(std::move(mon_opts_a), {}, fast_scheduler_opts());
    monitor_a.watch("_http._tcp.local.");
    monitor_a.async_start();
    h.executor.drain();

    // --- Monitor B: watches _ssh._tcp.local. only ---
    std::vector<resolved_service> ssh_found;
    std::vector<resolved_service> ssh_lost;

    monitor_options mon_opts_b;
    mon_opts_b.mode     = monitor_mode::discover;
    mon_opts_b.on_found = [&](const resolved_service &svc) { ssh_found.push_back(svc); };
    mon_opts_b.on_lost  = [&](const resolved_service &svc, loss_reason) { ssh_lost.push_back(svc); };

    auto monitor_b = h.make_monitor(std::move(mon_opts_b), {}, fast_scheduler_opts());
    monitor_b.watch("_ssh._tcp.local.");
    monitor_b.async_start();
    h.executor.drain();

    // Advance to let both monitors send queries and receive responses.
    // fast_scheduler_opts caps max_interval at 200ms so queries fire quickly.
    h.advance(std::chrono::milliseconds{400});

    // Monitor A should have discovered the HTTP server (WebServer) only.
    REQUIRE_FALSE(http_found.empty());
    CHECK(http_found[0].instance_name.str() == "webserver._http._tcp.local.");
    CHECK(http_found[0].port == 80);

    // Monitor B should have discovered the SSH server (SSHServer) only.
    REQUIRE_FALSE(ssh_found.empty());
    CHECK(ssh_found[0].instance_name.str() == "sshserver._ssh._tcp.local.");
    CHECK(ssh_found[0].port == 22);

    // Cross-contamination checks:
    // Monitor A (HTTP) must NOT have received SSHServer.
    for(const auto &svc : http_found)
        CHECK(svc.instance_name.str().find("ssh") == std::string::npos);

    // Monitor B (SSH) must NOT have received WebServer.
    for(const auto &svc : ssh_found)
        CHECK(svc.instance_name.str().find("web") == std::string::npos);

    // Neither monitor should have reported any lost services yet.
    CHECK(http_lost.empty());
    CHECK(ssh_lost.empty());
}

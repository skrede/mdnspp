// tests/local_bus_rfc_compliance_test.cpp
//
// RFC 6762 compliance integration tests using the deterministic local bus.
// All tests use local_harness (shared executor + bus) and test_clock for
// zero-wall-clock-time deterministic timing.
//
// TEST-03: Known-answer suppression end-to-end.
// TEST-04: Duplicate answer suppression across queriers.
// TEST-06: TC bit multi-packet accumulation end-to-end.
// TEST-07: Cache-flush propagation across monitors.

#include "mdnspp/local/local_harness.h"
#include "mdnspp/local/local_socket.h"

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

#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_response.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <optional>

using namespace mdnspp;
using mdnspp::local::local_harness;
using mdnspp::local::local_socket;
using mdnspp::testing::test_clock;

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
// Capping both initial_interval and max_interval at 200ms ensures erase_expired()
// is called frequently enough within the test advance window.
mdns_options fast_scheduler_opts()
{
    mdns_options opts;
    opts.initial_interval = std::chrono::milliseconds{200};
    opts.max_interval     = std::chrono::milliseconds{200};
    return opts;
}

// Build mdns_options with a very short response delay for deterministic tests.
// response_delay_min == response_delay_max makes the delay deterministic (1ms).
mdns_options fast_response_opts(std::chrono::milliseconds delay = std::chrono::milliseconds{1})
{
    mdns_options opts;
    opts.initial_interval   = std::chrono::milliseconds{200};
    opts.max_interval       = std::chrono::milliseconds{200};
    opts.response_delay_min = delay;
    opts.response_delay_max = delay;
    return opts;
}

// Multicast endpoint used by the local bus (loopback mDNS).
endpoint mdns_multicast_ep()
{
    return endpoint{"224.0.0.251", 5353};
}

// Inject raw bytes onto the bus as if sent from a transient socket.
// The injector socket is created, sends, then destroyed (deregisters from bus).
// The send enqueues the packet; drain() is needed to deliver it.
void inject(local_harness &h, std::span<const std::byte> data)
{
    local_socket<test_clock> injector{h.executor};
    injector.send(mdns_multicast_ep(), data);
}

} // namespace

// ---------------------------------------------------------------------------
// TEST-03: Known-answer suppression end-to-end
// ---------------------------------------------------------------------------
//
// RFC 6762 §7.1: A responder must not send an answer if the querier's known-answer
// list includes that answer with remaining TTL >= 50% of the record's TTL.
//
// Verification approach: Use basic_observer (pure listener, never sends queries) to
// count PTR records arriving on the bus. Inject two queries — one with a matching
// known-answer (suppression expected) and one without (response expected).

TEST_CASE("Known-answer suppression", "[local][rfc]")
{
    local_harness h;

    // Server with 1ms response delay so timing is deterministic.
    // Track which queries the server receives and whether it suppresses.
    int queries_received_by_server  = 0;
    int responses_suppressed        = 0;
    int responses_scheduled         = 0;

    service_options srv_opts;
    srv_opts.respond_to_meta_queries    = false;
    srv_opts.suppress_known_answers     = true;
    // Injector sockets are assigned ports >= 10000 by local_bus, which are not port 5353.
    // Without this, the server treats injected queries as legacy unicast and processes them
    // in a separate code path that bypasses known-answer suppression and on_query.
    srv_opts.respond_to_legacy_unicast  = false;
    srv_opts.on_query = [&](const endpoint &, dns_type, response_mode)
    {
        ++queries_received_by_server;
    };

    // Disable loopback so the server's own multicast announcements do not feed
    // back into m_dup_suppression and suppress the response to the plain query.
    socket_options srv_sock;
    srv_sock.multicast_loopback = loopback_mode::disabled;

    auto server = h.make_server(
        make_service("KnownServer._http._tcp.local.", "_http._tcp.local.",
                     "knownserver.local.", 9000),
        std::move(srv_opts), std::move(srv_sock), fast_response_opts());

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    // Observer: pure packet listener — does NOT send queries itself.
    // Counts PTR records that appear on the bus (from both query answer sections
    // and actual server responses).
    int ptr_records_received = 0;

    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        if(std::holds_alternative<record_ptr>(rec))
        {
            const auto &ptr = std::get<record_ptr>(rec);
            if(ptr.name == "_http._tcp.local.")
                ++ptr_records_received;
        }
    };

    auto obs = h.make_observer(std::move(obs_opts));
    obs.async_observe();
    h.executor.drain();

    // --- Part A: query WITH PTR known-answer (TTL=4500 >= 50% threshold=2250) ---
    // Server receives the query (on_query fires), checks known-answers, and suppresses.

    record_ptr ptr_ka;
    ptr_ka.name     = "_http._tcp.local.";
    ptr_ka.ttl      = 4500; // >= threshold (4500 * 0.5 = 2250)
    ptr_ka.rclass   = dns_class::in;
    ptr_ka.ptr_name = "knownserver._http._tcp.local.";

    std::vector<mdns_record_variant> ka_list{ptr_ka};
    auto query_with_ka = detail::build_dns_query("_http._tcp.local.", dns_type::ptr, ka_list);

    inject(h, std::span<const std::byte>(query_with_ka));
    h.advance(std::chrono::milliseconds{10});

    // Server must have received the KA query exactly once.
    CHECK(queries_received_by_server == 1);

    // The KA query packet itself has 1 PTR in answer section; observer counts it.
    // Server suppresses — no server response — observer counts nothing extra.
    int count_after_ka = ptr_records_received;
    CHECK(count_after_ka == 1);

    // --- Part B: plain query without known-answer ---
    // Server receives query (on_query fires again) and responds.

    auto query_no_ka = detail::build_dns_query("_http._tcp.local.", dns_type::ptr);
    inject(h, std::span<const std::byte>(query_no_ka));

    // Deliver query, arm response timer; then fire it in next advance.
    h.advance(std::chrono::milliseconds{2});
    h.advance(std::chrono::milliseconds{5});

    // Server must have received both queries.
    CHECK(queries_received_by_server == 2);

    // Suppress counters are unused for now; silence warnings.
    (void)responses_suppressed;
    (void)responses_scheduled;

    // Server responded to plain query — observer sees the additional PTR record.
    CHECK(ptr_records_received > count_after_ka);
}

// ---------------------------------------------------------------------------
// TEST-04: Duplicate answer suppression across queriers
// ---------------------------------------------------------------------------
//
// RFC 6762 §7.4: A querier that sees a multicast response to its own query (or
// another querier's query) should not trigger duplicate on_found events for the
// same service.
//
// Verification: Two monitors on the same bus both watch the same service type.
// The server responds via multicast when either monitor queries. Each monitor's
// on_found should fire exactly once, regardless of how many multicast responses
// it receives.

TEST_CASE("Duplicate answer suppression across queriers", "[local][rfc]")
{
    local_harness h;

    // Server with short response delay.
    service_options srv_opts;
    srv_opts.respond_to_meta_queries = false;

    auto server = h.make_server(
        make_service("DupServer._http._tcp.local.", "_http._tcp.local.",
                     "dupserver.local.", 9100),
        std::move(srv_opts), {}, fast_response_opts());

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    // Two monitors watching the same service type.
    int found_a = 0;
    int found_b = 0;

    monitor_options opts_a;
    opts_a.mode     = monitor_mode::discover;
    opts_a.on_found = [&](const resolved_service &) { ++found_a; };

    monitor_options opts_b;
    opts_b.mode     = monitor_mode::discover;
    opts_b.on_found = [&](const resolved_service &) { ++found_b; };

    auto monitor_a = h.make_monitor(std::move(opts_a), {}, fast_scheduler_opts());
    auto monitor_b = h.make_monitor(std::move(opts_b), {}, fast_scheduler_opts());

    monitor_a.watch("_http._tcp.local.");
    monitor_b.watch("_http._tcp.local.");

    monitor_a.async_start();
    monitor_b.async_start();
    h.executor.drain();

    // Advance to let both monitors' initial queries fire and the server respond.
    // The scheduler interval is 200ms. Both monitors fire at ~200ms; the server
    // responds via multicast (1ms delay) so both see the response at ~201ms.
    h.advance(std::chrono::milliseconds{200}); // scheduler ticks, queries sent
    h.advance(std::chrono::milliseconds{10});  // response delivery

    // Both monitors must have discovered the service exactly once.
    // Even though both receive the same multicast response, on_found fires only once
    // per instance per monitor (RFC 6762 duplicate suppression in record_cache).
    CHECK(found_a == 1);
    CHECK(found_b == 1);

    // Advance through another query round to confirm no duplicates appear.
    h.advance(std::chrono::milliseconds{400});

    // Still exactly one discovery per monitor.
    CHECK(found_a == 1);
    CHECK(found_b == 1);
}

// ---------------------------------------------------------------------------
// TEST-06: TC bit multi-packet accumulation
// ---------------------------------------------------------------------------
//
// RFC 6762 §6: When a query arrives with TC=1, the responder defers processing
// and waits for continuation packets from the same sender. It accumulates known-
// answer sections across all TC=1 packets from the same source, then processes
// the merged result when the TC wait timer fires.
//
// Verification:
//   1. Server is live.
//   2. From the SAME injector socket (same source endpoint), send two TC=1 packets:
//      - pkt1: PTR + SRV + TXT in the known-answer section
//      - pkt2: A in the known-answer section
//   3. Together they suppress all records the server would send.
//   4. After the TC wait timer fires, on_tc_continuation fires with the merged count.
//   5. Server finds all records suppressed and does NOT send a response.
//   6. A passive observer sees PTR records only from the query packets themselves
//      (answer sections), not from a server response.

TEST_CASE("TC bit multi-packet accumulation", "[local][rfc]")
{
    local_harness h;

    // Track TC continuation callback.
    std::size_t tc_merged_count = 0;
    bool tc_callback_fired = false;

    service_options srv_opts;
    srv_opts.respond_to_meta_queries = false;
    srv_opts.suppress_known_answers  = true;
    srv_opts.on_tc_continuation = [&](const endpoint &, std::size_t count)
    {
        tc_callback_fired = true;
        tc_merged_count   = count;
    };

    // Use deterministic TC wait: exactly 400ms on both ends.
    mdns_options srv_mdns;
    srv_mdns.response_delay_min  = std::chrono::milliseconds{1};
    srv_mdns.response_delay_max  = std::chrono::milliseconds{1};
    srv_mdns.tc_wait_min         = std::chrono::milliseconds{400};
    srv_mdns.tc_wait_max         = std::chrono::milliseconds{400};

    auto server = h.make_server(
        make_service("TcServer._http._tcp.local.", "_http._tcp.local.",
                     "tcserver.local.", 9200),
        std::move(srv_opts), {}, std::move(srv_mdns));

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    // Passive observer: counts PTR records with name _http._tcp.local. that arrive
    // on the bus. This includes PTR records from both injected query packets (in their
    // answer sections) and any server response packets.
    int ptr_bus_count = 0;

    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        if(std::holds_alternative<record_ptr>(rec))
        {
            const auto &ptr = std::get<record_ptr>(rec);
            if(ptr.name == "_http._tcp.local.")
                ++ptr_bus_count;
        }
    };

    auto obs = h.make_observer(std::move(obs_opts));
    obs.async_observe();
    h.executor.drain();

    // Build known-answer records covering all types the server would send.
    record_ptr ptr_ka;
    ptr_ka.name     = "_http._tcp.local.";
    ptr_ka.ttl      = 4500;
    ptr_ka.rclass   = dns_class::in;
    ptr_ka.ptr_name = "tcserver._http._tcp.local.";

    record_srv srv_ka;
    srv_ka.name     = "tcserver._http._tcp.local.";
    srv_ka.ttl      = 4500;
    srv_ka.rclass   = dns_class::in;
    srv_ka.srv_name = "tcserver.local.";
    srv_ka.port     = 9200;

    record_txt txt_ka;
    txt_ka.name   = "tcserver._http._tcp.local.";
    txt_ka.ttl    = 4500;
    txt_ka.rclass = dns_class::in;

    record_a a_ka;
    a_ka.name           = "tcserver.local.";
    a_ka.ttl            = 4500;
    a_ka.rclass         = dns_class::in;
    a_ka.sender_address = "192.168.1.1";
    a_ka.address_string = "192.168.1.1";

    // Build two TC=1 packets that MUST come from the same source endpoint.
    // Both packets carry TC=1 so the server accumulates them (not processes pkt2 as
    // a normal query, which would bypass TC accumulation).
    // Packet 1: PTR + SRV + TXT
    std::vector<mdns_record_variant> kas_pkt1{ptr_ka, srv_ka, txt_ka};
    auto pkt1 = detail::build_dns_query("_http._tcp.local.", dns_type::ptr, kas_pkt1);
    pkt1[2] = static_cast<std::byte>(std::to_integer<uint8_t>(pkt1[2]) | 0x02u); // TC=1

    // Packet 2: A (continuation known-answer)
    std::vector<mdns_record_variant> kas_pkt2{a_ka};
    auto pkt2 = detail::build_dns_query("_http._tcp.local.", dns_type::ptr, kas_pkt2);
    pkt2[2] = static_cast<std::byte>(std::to_integer<uint8_t>(pkt2[2]) | 0x02u); // TC=1

    // Use a single persistent injector socket so both packets share the same source
    // endpoint. The TC accumulator keys entries by sender; a different socket would
    // be a different source and the records would not be merged.
    {
        local_socket<test_clock> injector{h.executor};

        // Inject pkt1 (TC=1, PTR+SRV+TXT).
        injector.send(mdns_multicast_ep(), std::span<const std::byte>(pkt1));
        h.executor.drain();

        // Advance half the TC wait window — timer must NOT have fired yet.
        h.advance(std::chrono::milliseconds{200});
        CHECK_FALSE(tc_callback_fired);

        // Inject pkt2 (TC=1, A) from the SAME socket (same source endpoint).
        injector.send(mdns_multicast_ep(), std::span<const std::byte>(pkt2));
        h.executor.drain();
    }

    // Advance past TC timer expiry (400ms from pkt1, 200ms already elapsed,
    // 250ms more pushes clock well past the 400ms mark).
    h.advance(std::chrono::milliseconds{250});

    // TC continuation callback must have fired.
    CHECK(tc_callback_fired);

    // The accumulator merged pkt1's records (PTR+SRV+TXT) with pkt2's record (A).
    // on_tc_continuation receives the total count of merged records.
    CHECK(tc_merged_count == 4);

    // Observer counted PTR records from both pkt1 (1 PTR in answer section) and pkt2
    // (0 PTR in answer section). If server suppresses correctly: count = 1.
    // If server incorrectly responded: count = 2 (extra from server response).
    CHECK(ptr_bus_count == 1);
}

// ---------------------------------------------------------------------------
// TEST-07: Cache-flush propagation across monitors
// ---------------------------------------------------------------------------
//
// RFC 6762 §10.2: A record with the cache-flush bit set asserts that this is the
// unique authoritative record for the name/type. Records from other origins for
// the same name/type must be evicted within one second.
//
// Verification:
//   1. Two monitors discover a server. Server records are cached under origin A.
//   2. A synthetic response from a different origin (B) is injected, adding
//      a stale A record under a different sender address.
//   3. The real server re-announces (update_service_info) with records including
//      cache_flush=true (which SRV, A, TXT records carry per RFC).
//   4. Both monitors' on_cache_flush callbacks fire because origin B's record
//      conflicts with the authoritative record from origin A.

TEST_CASE("Cache-flush propagation across monitors", "[local][rfc]")
{
    local_harness h;

    service_options srv_opts;
    srv_opts.respond_to_meta_queries = false;

    auto server = h.make_server(
        make_service("FlushServer._http._tcp.local.", "_http._tcp.local.",
                     "flushserver.local.", 9300),
        std::move(srv_opts), {}, fast_response_opts());

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    // Two monitors with on_cache_flush callbacks.
    int flush_a = 0;
    int flush_b = 0;
    int found_a = 0;
    int found_b = 0;

    cache_options copts_a;
    copts_a.on_cache_flush = [&](const cache_entry &, std::vector<cache_entry> flushed)
    {
        if(!flushed.empty())
            ++flush_a;
    };

    cache_options copts_b;
    copts_b.on_cache_flush = [&](const cache_entry &, std::vector<cache_entry> flushed)
    {
        if(!flushed.empty())
            ++flush_b;
    };

    monitor_options opts_a;
    opts_a.mode     = monitor_mode::discover;
    opts_a.on_found = [&](const resolved_service &) { ++found_a; };

    monitor_options opts_b;
    opts_b.mode     = monitor_mode::discover;
    opts_b.on_found = [&](const resolved_service &) { ++found_b; };

    auto monitor_a = h.make_monitor(std::move(opts_a), {}, fast_scheduler_opts(),
                                    std::move(copts_a));
    auto monitor_b = h.make_monitor(std::move(opts_b), {}, fast_scheduler_opts(),
                                    std::move(copts_b));

    monitor_a.watch("_http._tcp.local.");
    monitor_b.watch("_http._tcp.local.");

    monitor_a.async_start();
    monitor_b.async_start();
    h.executor.drain();

    // Advance to let both monitors discover the service via the server's announcement.
    // Scheduler fires at 200ms; server responds at 201ms (1ms delay); monitors
    // receive and fire on_found.
    h.advance(std::chrono::milliseconds{200});
    h.advance(std::chrono::milliseconds{10});

    REQUIRE(found_a >= 1);
    REQUIRE(found_b >= 1);

    // Inject a stale A record from a different origin (different IP = different rdata
    // AND different sender endpoint from the injector socket).
    // build_dns_response with cache_flush=true on A/SRV/TXT records is what the server
    // sends. We inject a response claiming flushserver.local. -> 10.0.0.99 (stale IP).
    // Both monitors cache this record under origin = injector's assigned endpoint.
    service_info stale_info = make_service("FlushServer._http._tcp.local.",
                                            "_http._tcp.local.",
                                            "flushserver.local.", 9300,
                                            "10.0.0.99");
    uint32_t stale_ttl = 4500;
    auto stale_pkt = detail::build_dns_response(stale_info, dns_type::a, stale_ttl);

    inject(h, std::span<const std::byte>(stale_pkt));
    h.executor.drain();

    // Now the real server re-announces (update_service_info triggers announcements
    // with the authoritative records, which carry cache_flush=true for SRV/A/TXT).
    // Each monitor receives the announcement from the server's endpoint. The A record
    // (flushserver.local. -> 192.168.1.1) has cache_flush=true. When inserted into
    // each monitor's cache, apply_cache_flush sees the stale entry from the injector
    // endpoint and marks it for eviction, firing on_cache_flush.
    server.update_service_info(
        make_service("FlushServer._http._tcp.local.", "_http._tcp.local.",
                     "flushserver.local.", 9300));

    // Advance to let announcements propagate (default announce_count=2,
    // announce_interval=1000ms — first announcement is immediate).
    h.advance(std::chrono::milliseconds{200});
    h.advance(std::chrono::milliseconds{50});

    // Both monitors received the cache-flush signal from the authoritative re-announcement.
    CHECK(flush_a >= 1);
    CHECK(flush_b >= 1);

    // Both monitors still consider the service found (cache-flush refreshed the record,
    // did not remove it — the service is still alive).
    CHECK(found_a >= 1);
    CHECK(found_b >= 1);
}

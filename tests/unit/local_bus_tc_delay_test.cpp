// tests/local_bus_tc_delay_test.cpp
//
// TC continuation delay integration tests.
// Verifies that basic_service_monitor spaces TC continuation packets using
// the tc_continuation_delay timer when tc_continuation_delay > 0.
//
// TEST-13: TC continuation delay: first packet immediate, subsequent delayed.
// TEST-14: TC continuation delay zero: all packets sent in same drain cycle.

#include "mdnspp/local/local_harness.h"
#include "mdnspp/local/local_socket.h"

#include "mdnspp/service_info.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_response.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstdint>
#include <cstddef>
#include <functional>

using namespace mdnspp;
using mdnspp::local::local_harness;
using mdnspp::local::local_socket;
using mdnspp::testing::test_clock;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

namespace {

// Build mdns_options with a short scheduler interval for deterministic timing
// and a small max_query_payload to force TC splits.
mdns_options fast_scheduler_opts(std::chrono::milliseconds tc_delay = {})
{
    mdns_options opts;
    opts.initial_interval      = std::chrono::milliseconds{200};
    opts.max_interval          = std::chrono::milliseconds{200};
    opts.tc_continuation_delay = tc_delay;
    opts.max_query_payload     = 200; // small payload to force TC splits
    return opts;
}

// Multicast endpoint used by the local bus (loopback mDNS).
endpoint mdns_multicast_ep()
{
    return endpoint{"224.0.0.251", 5353};
}

// Inject a synthetic PTR response from a transient socket so the monitor
// caches a PTR record for `_http._tcp.local.` pointing to `instance_name`.
void inject_ptr_response(local_harness &h,
                         std::string_view instance_name,
                         uint32_t ttl = 4500)
{
    service_info info;
    info.service_type = "_http._tcp.local.";
    info.service_name = std::string(instance_name);
    info.hostname     = "host.local.";
    info.port         = 80;
    info.address_ipv4 = "192.168.1.1";

    service_options opts;
    opts.ptr_ttl    = std::chrono::seconds{ttl};
    opts.srv_ttl    = std::chrono::seconds{ttl};
    opts.txt_ttl    = std::chrono::seconds{ttl};
    opts.a_ttl      = std::chrono::seconds{ttl};
    opts.aaaa_ttl   = std::chrono::seconds{ttl};
    opts.record_ttl = std::chrono::seconds{ttl};

    auto pkt = detail::build_dns_response(info, dns_type::ptr, opts);

    local_socket<test_clock> injector{h.executor};
    injector.send(mdns_multicast_ep(), std::span<const std::byte>(pkt));
    h.executor.drain();
}

} // namespace

// ---------------------------------------------------------------------------
// TEST-13: TC continuation delay spaces packets
// ---------------------------------------------------------------------------
//
// When tc_continuation_delay > 0 and the known-answer section spans multiple TC
// packets, the first packet is sent immediately and subsequent packets are sent
// after the timer fires.
//
// Exact tick verification:
//   - After advance(49ms): second packet NOT yet sent.
//   - After advance(1ms more, total 50ms): second packet IS sent.

TEST_CASE("TC continuation delay spaces packets", "[local][tc]")
{
    local_harness h;

    // Monitor with small max_query_payload to force TC splits and 50ms delay.
    auto mon_opts = fast_scheduler_opts(std::chrono::milliseconds{50});
    monitor_options m_opts;
    m_opts.mode = monitor_mode::discover;

    auto monitor = h.make_monitor(std::move(m_opts), {}, std::move(mon_opts));
    monitor.watch("_http._tcp.local.");
    monitor.async_start();
    h.executor.drain();

    // Inject enough PTR responses so the monitor caches >= 3 instances.
    // With max_query_payload=200, 3+ PTR records in the known-answer section
    // overflow into a second TC packet (each PTR RR is ~55 bytes,
    // base packet is ~34 bytes, so 3+ records exceed 200 bytes).
    inject_ptr_response(h, "Instance1._http._tcp.local.");
    inject_ptr_response(h, "Instance2._http._tcp.local.");
    inject_ptr_response(h, "Instance3._http._tcp.local.");
    inject_ptr_response(h, "Instance4._http._tcp.local.");

    // Count raw DNS query packets (QR=0) seen on the multicast endpoint.
    // DNS query: bit 7 of byte 2 in the DNS header == 0.
    std::vector<std::vector<std::byte>> query_packets;

    local_socket<test_clock> sniffer{h.executor};

    std::function<void()> arm_sniffer = [&]()
    {
        sniffer.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte> data)
        {
            if(data.size() >= 3 &&
               (std::to_integer<uint8_t>(data[2]) & 0x80u) == 0)
            {
                query_packets.push_back(std::vector<std::byte>(data.begin(), data.end()));
            }
            arm_sniffer();
        });
    };
    arm_sniffer();

    // Advance 200ms to fire the monitor's initial query.
    // The first TC packet is sent immediately; the second is queued behind the 50ms timer.
    h.advance(std::chrono::milliseconds{200});

    // After 200ms: first query packet must have arrived.
    REQUIRE(query_packets.size() >= 1u);

    std::size_t count_after_initial = query_packets.size();

    // Advance 49ms: NOT enough to fire the 50ms TC delay timer.
    h.advance(std::chrono::milliseconds{49});
    CHECK(query_packets.size() == count_after_initial);

    // Advance 1ms more (total 50ms from first packet): timer fires, second packet sent.
    h.advance(std::chrono::milliseconds{1});
    CHECK(query_packets.size() > count_after_initial);
}

// ---------------------------------------------------------------------------
// TEST-14: TC continuation delay zero sends all packets in same drain cycle
// ---------------------------------------------------------------------------
//
// When tc_continuation_delay == 0, all TC continuation packets are sent
// synchronously in the same drain cycle without any timer interleaving.

TEST_CASE("TC continuation delay zero sends all packets immediately", "[local][tc]")
{
    local_harness h;

    // Monitor with zero TC delay (default 0).
    auto mon_opts = fast_scheduler_opts();
    monitor_options m_opts;
    m_opts.mode = monitor_mode::discover;

    auto monitor = h.make_monitor(std::move(m_opts), {}, std::move(mon_opts));
    monitor.watch("_http._tcp.local.");
    monitor.async_start();
    h.executor.drain();

    // Inject enough instances to force TC splits.
    inject_ptr_response(h, "InstanceA._http._tcp.local.");
    inject_ptr_response(h, "InstanceB._http._tcp.local.");
    inject_ptr_response(h, "InstanceC._http._tcp.local.");
    inject_ptr_response(h, "InstanceD._http._tcp.local.");

    std::vector<std::vector<std::byte>> query_packets;

    local_socket<test_clock> sniffer{h.executor};

    std::function<void()> arm_sniffer = [&]()
    {
        sniffer.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte> data)
        {
            if(data.size() >= 3 &&
               (std::to_integer<uint8_t>(data[2]) & 0x80u) == 0)
            {
                query_packets.push_back(std::vector<std::byte>(data.begin(), data.end()));
            }
            arm_sniffer();
        });
    };
    arm_sniffer();

    // Advance 200ms to fire the scheduler.
    h.advance(std::chrono::milliseconds{200});

    // With zero delay, all TC packets are sent synchronously.
    // Multiple query packets must be present in the same drain window.
    CHECK(query_packets.size() > 1u);
}

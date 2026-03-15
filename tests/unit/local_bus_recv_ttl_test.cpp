// tests/unit/local_bus_recv_ttl_test.cpp
//
// Integration tests verifying receive_ttl_minimum packet filtering via local bus.
//
// TEST-13: receive_ttl_minimum filters packets below the threshold.
//
// These tests confirm PARAM-05c: receive_ttl_minimum in mdns_options is enforced
// in recv_loop -- packets with IP TTL below the threshold are silently discarded.
//
// Verification approach: inject DNS packets directly into the observer's local_socket
// with a controlled TTL, then confirm whether on_record fires based on the threshold.
//
// The inject-with-ttl path uses local_socket::deliver(from, data, ttl) which is the
// test-only overload added in phase 47-03.

#include "mdnspp/local/local_harness.h"
#include "mdnspp/local/local_socket.h"

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/basic_service_server.h"

#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/dns_response.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string>
#include <vector>
#include <cstdint>
#include <cstddef>

using namespace mdnspp;
using mdnspp::local::local_harness;
using mdnspp::local::local_socket;
using mdnspp::testing::test_clock;

namespace {

service_info make_service(std::string_view name,
                          std::string_view type,
                          std::string_view host,
                          uint16_t port)
{
    service_info info;
    info.service_name = std::string(name);
    info.service_type = std::string(type);
    info.hostname     = std::string(host);
    info.port         = port;
    info.address_ipv4 = "192.168.1.1";
    return info;
}

// Build a minimal mDNS PTR response packet for injection.
// Uses the real DNS response builder so the observer can parse it.
std::vector<std::byte> make_ptr_response(std::string_view service_name,
                                          std::string_view service_type,
                                          std::string_view host,
                                          uint16_t port)
{
    service_options srv_opts;
    return detail::build_dns_response(
        make_service(service_name, service_type, host, port),
        dns_type::ptr,
        srv_opts);
}

} // namespace

// ---------------------------------------------------------------------------
// TEST-13a: receive_ttl_minimum=255 filters TTL=254 packets
// ---------------------------------------------------------------------------
//
// Observer configured with receive_ttl_minimum=255 (the RFC default).
// Packets delivered with TTL=254 (one hop below link-local minimum) are dropped.
// Packets delivered with TTL=255 are processed normally.

TEST_CASE("receive_ttl_minimum=255 drops TTL=254 packets", "[local][ttl-filter]")
{
    local_harness h;

    mdns_options mdns_opts;
    mdns_opts.receive_ttl_minimum = 255;

    int records_received = 0;
    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &)
    {
        ++records_received;
    };

    auto observer = h.make_observer(std::move(obs_opts), {}, std::move(mdns_opts));
    observer.async_observe();
    h.executor.drain();

    auto pkt = make_ptr_response("TtlTest._http._tcp.local.",
                                  "_http._tcp.local.",
                                  "ttltest.local.", 9000);

    endpoint from{"192.168.1.50", 5353};

    // Inject with TTL=254 — must be dropped.
    observer.socket().deliver(from, std::span<const std::byte>(pkt), uint8_t{254});
    h.executor.drain();

    REQUIRE(records_received == 0);

    // Inject with TTL=255 — must be processed.
    observer.socket().deliver(from, std::span<const std::byte>(pkt), uint8_t{255});
    h.executor.drain();

    REQUIRE(records_received >= 1);
}

// ---------------------------------------------------------------------------
// TEST-13b: receive_ttl_minimum=0 accepts all TTL values including TTL=0
// ---------------------------------------------------------------------------
//
// receive_ttl_minimum=0 disables filtering entirely — all packets pass.

TEST_CASE("receive_ttl_minimum=0 accepts all TTL values", "[local][ttl-filter]")
{
    local_harness h;

    mdns_options mdns_opts;
    mdns_opts.receive_ttl_minimum = 0;

    int records_received = 0;
    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &)
    {
        ++records_received;
    };

    auto observer = h.make_observer(std::move(obs_opts), {}, std::move(mdns_opts));
    observer.async_observe();
    h.executor.drain();

    auto pkt = make_ptr_response("TtlMin0._http._tcp.local.",
                                  "_http._tcp.local.",
                                  "ttlmin0.local.", 9001);

    endpoint from{"192.168.1.51", 5353};

    // Inject with TTL=0 — must be processed (minimum is 0, all pass).
    observer.socket().deliver(from, std::span<const std::byte>(pkt), uint8_t{0});
    h.executor.drain();

    REQUIRE(records_received >= 1);
}

// ---------------------------------------------------------------------------
// TEST-13c: receive_ttl_minimum=1 accepts TTL=1 but drops TTL=0
// ---------------------------------------------------------------------------
//
// receive_ttl_minimum=1: TTL=1 passes (>= 1), TTL=0 is dropped (< 1).

TEST_CASE("receive_ttl_minimum=1 accepts TTL=1, drops TTL=0", "[local][ttl-filter]")
{
    local_harness h;

    mdns_options mdns_opts;
    mdns_opts.receive_ttl_minimum = 1;

    int records_ttl1 = 0;
    int records_ttl0 = 0;

    observer_options obs_opts1;
    obs_opts1.on_record = [&](const endpoint &, const mdns_record_variant &)
    {
        ++records_ttl1;
    };

    observer_options obs_opts0;
    obs_opts0.on_record = [&](const endpoint &, const mdns_record_variant &)
    {
        ++records_ttl0;
    };

    // Two separate observers with different service names to avoid conflicts.
    mdns_options mdns_opts2;
    mdns_opts2.receive_ttl_minimum = 1;

    auto obs1 = h.make_observer(std::move(obs_opts1), {}, mdns_opts);
    obs1.async_observe();
    h.executor.drain();

    auto obs2 = h.make_observer(std::move(obs_opts0), {}, mdns_opts2);
    obs2.async_observe();
    h.executor.drain();

    endpoint from{"192.168.1.52", 5353};

    auto pkt_ttl1 = make_ptr_response("TtlOne1._http._tcp.local.",
                                       "_http._tcp.local.",
                                       "ttlone1.local.", 9002);

    auto pkt_ttl0 = make_ptr_response("TtlZero0._http._tcp.local.",
                                       "_http._tcp.local.",
                                       "ttlzero0.local.", 9003);

    // Inject TTL=1 into obs1 — must pass (1 >= 1).
    obs1.socket().deliver(from, std::span<const std::byte>(pkt_ttl1), uint8_t{1});
    h.executor.drain();

    REQUIRE(records_ttl1 >= 1);

    // Inject TTL=0 into obs2 — must be dropped (0 < 1).
    obs2.socket().deliver(from, std::span<const std::byte>(pkt_ttl0), uint8_t{0});
    h.executor.drain();

    REQUIRE(records_ttl0 == 0);
}

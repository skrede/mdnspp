// tests/unit/inproc_bus_legacy_unicast_test.cpp
//
// Integration tests verifying legacy unicast handling via the inproc bus.
//
// TEST-14: Legacy unicast query from non-5353 port triggers unicast response
//          with TTLs capped at mdns_options::legacy_unicast_ttl.
//
// RFC 6762 §6.7: Queries received from source ports other than 5353 are
// "legacy unicast" queries. The responder must send a unicast reply directly
// to the sender with all TTLs capped at legacy_unicast_ttl (default 10s).
//
// Verification approach:
//   - Use inproc::inproc_socket_options::port_override to assign a non-5353 source port to
//     an inproc_socket, simulating a legacy DNS-SD client.
//   - Server receives the query, detects source_port != 5353, and sends
//     the response unicast to the legacy socket's endpoint.
//   - A separate observer monitors the multicast group to confirm that no
//     multicast response is sent for the legacy unicast case.
//   - The legacy socket captures the unicast response and verifies TTL cap.
//
// TEST-15 closure: TC-split reassembly is verified by the existing TEST-06
// ("TC bit multi-packet accumulation" in inproc_bus_rfc_compliance_test.cpp)
// which proves that TC=1 first packet + continuation packet are accumulated
// and processed as a single query with combined known-answer list.

#include "mdnspp/inproc/inproc_harness.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/basic_service_server.h"

#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/dns_response.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string>
#include <vector>
#include <variant>
#include <cstdint>
#include <cstddef>

using namespace mdnspp;
using mdnspp::inproc::inproc_harness;
using mdnspp::inproc::inproc_socket;
using mdnspp::testing::test_clock;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

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

endpoint mdns_multicast_ep()
{
    return endpoint{"224.0.0.251", 5353};
}

std::vector<mdns_record_variant> parse_records(std::span<const std::byte> data)
{
    std::vector<mdns_record_variant> records;
    detail::walk_dns_frame(data, endpoint{}, [&](mdns_record_variant rv)
    {
        records.push_back(std::move(rv));
    });
    return records;
}

uint32_t max_ttl(const std::vector<mdns_record_variant> &records)
{
    uint32_t m = 0;
    for(const auto &rec : records)
        m = (std::max)(m, std::visit([](const auto &r) { return r.ttl; }, rec));
    return m;
}

}

// ---------------------------------------------------------------------------
// TEST-14: Legacy unicast query from non-5353 port gets unicast response
//          with TTLs capped at legacy_unicast_ttl
// ---------------------------------------------------------------------------

TEST_CASE("Legacy unicast query from non-5353 port gets unicast response with capped TTL",
          "[inproc][legacy-unicast]")
{
    inproc_harness h;

    service_options srv_opts;
    srv_opts.respond_to_legacy_unicast = true;
    srv_opts.respond_to_meta_queries   = false;
    inproc::inproc_socket_options srv_sock;
    srv_sock.multicast_loopback = loopback_mode::disabled;

    mdns_options srv_mdns;
    srv_mdns.legacy_unicast_ttl = std::chrono::seconds{10};

    auto server = h.make_server(
        make_service("LegacyServer._http._tcp.local.", "_http._tcp.local.",
                     "legacy.local.", 8080),
        std::move(srv_opts), std::move(srv_sock), std::move(srv_mdns));

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    int multicast_response_count = 0;
    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        if(std::holds_alternative<record_ptr>(rec))
        {
            const auto &ptr = std::get<record_ptr>(rec);
            if(ptr.name == "_http._tcp.local.")
                ++multicast_response_count;
        }
    };

    auto observer = h.make_observer(std::move(obs_opts));
    observer.async_observe();
    h.executor.drain();

    inproc::inproc_socket_options legacy_opts;
    legacy_opts.port_override         = uint16_t{12345};
    legacy_opts.multicast_loopback    = loopback_mode::disabled;

    inproc_socket<test_clock> legacy_client{h.executor, legacy_opts};
    const endpoint legacy_ep = legacy_client.assigned_endpoint();
    REQUIRE(legacy_ep.port == 12345);

    std::vector<std::byte> received_data;
    endpoint received_from{};

    legacy_client.async_receive(
        [&](std::error_code, const recv_metadata &meta, std::span<std::byte> data)
        {
            received_from = meta.sender;
            received_data.assign(data.begin(), data.end());
        });

    auto query = detail::build_dns_query("_http._tcp.local.", dns_type::ptr);
    legacy_client.send(mdns_multicast_ep(), std::span<const std::byte>(query));

    h.executor.drain();

    REQUIRE_FALSE(received_data.empty());

    auto records = parse_records(std::span<const std::byte>(received_data));
    REQUIRE_FALSE(records.empty());

    uint32_t observed_max_ttl = max_ttl(records);
    CHECK(observed_max_ttl <= 10u);

    CHECK(multicast_response_count == 0);
}

// ---------------------------------------------------------------------------
// Normal query from port 5353 gets multicast response with full TTLs
// ---------------------------------------------------------------------------

TEST_CASE("Normal query from port 5353 gets multicast response with full TTLs",
          "[inproc][legacy-unicast]")
{
    inproc_harness h;

    service_options srv_opts;
    srv_opts.respond_to_legacy_unicast = true;
    srv_opts.respond_to_meta_queries   = false;
    srv_opts.ptr_ttl  = std::chrono::seconds{4500};
    srv_opts.srv_ttl  = std::chrono::seconds{4500};
    srv_opts.a_ttl    = std::chrono::seconds{4500};
    srv_opts.txt_ttl  = std::chrono::seconds{4500};
    srv_opts.fallback_record_ttl = std::chrono::seconds{4500};
    inproc::inproc_socket_options srv_sock;
    srv_sock.multicast_loopback = loopback_mode::disabled;

    mdns_options srv_mdns;
    srv_mdns.response_delay_min = std::chrono::milliseconds{1};
    srv_mdns.response_delay_max = std::chrono::milliseconds{1};

    auto server = h.make_server(
        make_service("NormalServer._http._tcp.local.", "_http._tcp.local.",
                     "normal.local.", 9090),
        std::move(srv_opts), std::move(srv_sock), std::move(srv_mdns));

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    int multicast_ptr_count = 0;
    uint32_t observed_ptr_ttl = 0;
    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        if(std::holds_alternative<record_ptr>(rec))
        {
            const auto &ptr = std::get<record_ptr>(rec);
            if(ptr.name == "_http._tcp.local.")
            {
                ++multicast_ptr_count;
                observed_ptr_ttl = ptr.ttl;
            }
        }
    };

    auto observer = h.make_observer(std::move(obs_opts));
    observer.async_observe();
    h.executor.drain();

    inproc_socket<test_clock> normal_client{h.executor};
    REQUIRE(normal_client.assigned_endpoint().port == 5353);

    auto query = detail::build_dns_query("_http._tcp.local.", dns_type::ptr);
    normal_client.send(mdns_multicast_ep(), std::span<const std::byte>(query));

    h.executor.drain();

    h.advance(std::chrono::milliseconds{5});

    REQUIRE(multicast_ptr_count >= 1);

    CHECK(observed_ptr_ttl == 4500u);
}

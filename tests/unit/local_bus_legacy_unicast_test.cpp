// tests/unit/local_bus_legacy_unicast_test.cpp
//
// Integration tests verifying legacy unicast handling via the local bus.
//
// TEST-14: Legacy unicast query from non-5353 port triggers unicast response
//          with TTLs capped at mdns_options::legacy_unicast_ttl.
//
// RFC 6762 §6.7: Queries received from source ports other than 5353 are
// "legacy unicast" queries. The responder must send a unicast reply directly
// to the sender with all TTLs capped at legacy_unicast_ttl (default 10s).
//
// Verification approach:
//   - Use socket_options::port_override to assign a non-5353 source port to
//     a local_socket, simulating a legacy DNS-SD client.
//   - Server receives the query, detects source_port != 5353, and sends
//     the response unicast to the legacy socket's endpoint.
//   - A separate observer monitors the multicast group to confirm that no
//     multicast response is sent for the legacy unicast case.
//   - The legacy socket captures the unicast response and verifies TTL cap.
//
// TEST-15 closure: TC-split reassembly is verified by the existing TEST-06
// ("TC bit multi-packet accumulation" in local_bus_rfc_compliance_test.cpp)
// which proves that TC=1 first packet + continuation packet are accumulated
// and processed as a single query with combined known-answer list.

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

// Multicast endpoint used by the local bus (loopback mDNS).
endpoint mdns_multicast_ep()
{
    return endpoint{"224.0.0.251", 5353};
}

// Collect all mdns_record_variant records from a raw DNS wire packet.
// Returns an empty vector for malformed or question-only packets.
std::vector<mdns_record_variant> parse_records(std::span<const std::byte> data)
{
    std::vector<mdns_record_variant> records;
    detail::walk_dns_frame(data, endpoint{}, [&](mdns_record_variant rv)
    {
        records.push_back(std::move(rv));
    });
    return records;
}

// Extract the maximum TTL from a set of parsed records.
// Returns 0 for an empty record set.
uint32_t max_ttl(const std::vector<mdns_record_variant> &records)
{
    uint32_t m = 0;
    for(const auto &rec : records)
        m = std::max(m, std::visit([](const auto &r) { return r.ttl; }, rec));
    return m;
}

} // namespace

// ---------------------------------------------------------------------------
// TEST-14: Legacy unicast query from non-5353 port gets unicast response
//          with TTLs capped at legacy_unicast_ttl
// ---------------------------------------------------------------------------
//
// RFC 6762 §6.7: Queries arriving from source port != 5353 are legacy unicast.
// The responder must reply unicast with TTLs capped at legacy_unicast_ttl.
//
// This test uses socket_options::port_override to assign port 12345 to the
// legacy client socket. The server detects source_port=12345 != 5353 and
// responds unicast to "127.0.0.X:12345".

TEST_CASE("Legacy unicast query from non-5353 port gets unicast response with capped TTL",
          "[local][legacy-unicast]")
{
    local_harness h;

    // Server with full per-type TTLs and legacy unicast enabled.
    service_options srv_opts;
    srv_opts.respond_to_legacy_unicast = true;
    srv_opts.respond_to_meta_queries   = false;
    // Disable loopback so the server's own announcements don't feed back
    // into dup suppression and interfere with the unicast response path.
    socket_options srv_sock;
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

    // Observer on the multicast group: confirms no multicast response is sent
    // for the legacy unicast query (the response goes direct-unicast only).
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

    // Create a legacy client socket with port_override=12345.
    // The bus assigns endpoint "127.0.0.N:12345" (N = next available IP).
    // The server detects source_port=12345 != 5353 → legacy unicast path.
    // Disable loopback so the client does not receive its own outgoing query back
    // from the multicast group delivery — only the server's unicast response arrives.
    socket_options legacy_opts;
    legacy_opts.port_override         = uint16_t{12345};
    legacy_opts.multicast_loopback    = loopback_mode::disabled;

    local_socket<test_clock> legacy_client{h.executor, legacy_opts};
    const endpoint legacy_ep = legacy_client.assigned_endpoint();
    REQUIRE(legacy_ep.port == 12345);

    // Capture the unicast response delivered to the legacy client.
    std::vector<std::byte> received_data;
    endpoint received_from{};

    legacy_client.async_receive(
        [&](const recv_metadata &meta, std::span<std::byte> data)
        {
            received_from = meta.sender;
            received_data.assign(data.begin(), data.end());
        });

    // Send PTR query from the legacy socket to the multicast group.
    auto query = detail::build_dns_query("_http._tcp.local.", dns_type::ptr);
    legacy_client.send(mdns_multicast_ep(), std::span<const std::byte>(query));

    // Drain: deliver query → server processes it → server sends unicast response
    // to the legacy client's endpoint → legacy client's pending receive fires.
    h.executor.drain();

    // Legacy client must have received exactly one unicast response.
    REQUIRE_FALSE(received_data.empty());

    // Parse the response and verify TTL cap.
    auto records = parse_records(std::span<const std::byte>(received_data));
    REQUIRE_FALSE(records.empty());

    uint32_t observed_max_ttl = max_ttl(records);
    // All TTLs must be <= legacy_unicast_ttl (10 seconds).
    CHECK(observed_max_ttl <= 10u);

    // No multicast PTR response was sent (legacy unicast path exits early).
    CHECK(multicast_response_count == 0);
}

// ---------------------------------------------------------------------------
// Normal query from port 5353 gets multicast response with full TTLs
// ---------------------------------------------------------------------------
//
// A socket with the default bus port (5353) sends a PTR query. The server
// processes it through the normal multicast response path. TTLs are not capped.

TEST_CASE("Normal query from port 5353 gets multicast response with full TTLs",
          "[local][legacy-unicast]")
{
    local_harness h;

    // Server with per-type TTLs well above 10s (legacy_unicast_ttl default).
    service_options srv_opts;
    srv_opts.respond_to_legacy_unicast = true;
    srv_opts.respond_to_meta_queries   = false;
    srv_opts.ptr_ttl  = std::chrono::seconds{4500};
    srv_opts.srv_ttl  = std::chrono::seconds{4500};
    srv_opts.a_ttl    = std::chrono::seconds{4500};
    srv_opts.txt_ttl  = std::chrono::seconds{4500};
    srv_opts.record_ttl = std::chrono::seconds{4500};
    // Disable loopback on server so its announcements don't cause dup suppression.
    socket_options srv_sock;
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

    // Observer counts PTR records arriving on the multicast bus.
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

    // Normal query socket — uses the default bus port (5353).
    local_socket<test_clock> normal_client{h.executor};
    REQUIRE(normal_client.assigned_endpoint().port == 5353);

    // Send PTR query from the normal socket to the multicast group.
    auto query = detail::build_dns_query("_http._tcp.local.", dns_type::ptr);
    normal_client.send(mdns_multicast_ep(), std::span<const std::byte>(query));

    // First drain: deliver query → server schedules multicast response (1ms delay).
    h.executor.drain();

    // Second advance: response timer (1ms) fires → response delivered to multicast group.
    h.advance(std::chrono::milliseconds{5});

    // The observer must have seen at least one PTR record from the server response.
    REQUIRE(multicast_ptr_count >= 1);

    // TTL must NOT be capped — full 4500s should appear on wire.
    CHECK(observed_ptr_ttl == 4500u);
}

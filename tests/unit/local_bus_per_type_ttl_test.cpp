// tests/unit/local_bus_per_type_ttl_test.cpp
//
// Integration tests verifying per-type TTL values appear in wire responses.
//
// TEST-11a: Per-type TTLs appear in wire responses (announcement path).
// TEST-11b: Goodbye uses TTL=0 for all record types.
//
// These tests confirm PARAM-05a: per-type TTL fields in service_options are
// wired into response construction and produce the correct TTL values on the wire.
//
// Verification approach: the announcement packet uses dns_type::any, which
// dispatches per-type TTLs from service_options. An observer captures the
// parsed records (which include the on-wire TTL field) and verifies each
// record type carries the value configured in service_options.

#include "mdnspp/local/local_harness.h"

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"
#include "mdnspp/mdns_options.h"
#include "mdnspp/service_options.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/basic_service_server.h"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>
#include <vector>
#include <variant>
#include <cstdint>
#include <cstddef>
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
                          uint16_t port)
{
    service_info info;
    info.service_name = std::string(name);
    info.service_type = std::string(type);
    info.hostname     = std::string(host);
    info.port         = port;
    info.address_ipv4 = "192.168.1.1";
    info.address_ipv6 = "::1";
    return info;
}

// Build server options with distinct per-type TTLs for easy identification.
// PTR=100, SRV=200, TXT=300, A=400, AAAA=500, fallback=600.
service_options distinct_ttl_opts()
{
    service_options opts;
    opts.ptr_ttl    = std::chrono::seconds{100};
    opts.srv_ttl    = std::chrono::seconds{200};
    opts.txt_ttl    = std::chrono::seconds{300};
    opts.a_ttl      = std::chrono::seconds{400};
    opts.aaaa_ttl   = std::chrono::seconds{500};
    opts.record_ttl = std::chrono::seconds{600};
    opts.respond_to_meta_queries = false;
    return opts;
}

} // namespace

// ---------------------------------------------------------------------------
// TEST-11a: Per-type TTLs appear in wire responses
// ---------------------------------------------------------------------------
//
// A server configured with distinct per-type TTLs (PTR=100, SRV=200, A=400,
// AAAA=500) broadcasts its announcement. An observer captures the records
// and verifies each type carries the expected TTL value.
//
// The announcement uses dns_type::any, which dispatches per-type TTLs from
// service_options. The observer's on_record callback receives parsed records
// that include the on-wire TTL field.

TEST_CASE("Per-type TTLs appear in wire responses", "[local][ttl]")
{
    local_harness h;

    // Server with distinct per-type TTLs.
    // Disable loopback so announcements don't feed back into the server's own
    // dup suppression and cause unwanted suppression in later stages.
    socket_options srv_sock;
    srv_sock.multicast_loopback = loopback_mode::disabled;

    auto server = h.make_server(
        make_service("PerTypeTtl._http._tcp.local.", "_http._tcp.local.",
                     "pertypettl.local.", 8080),
        distinct_ttl_opts(), std::move(srv_sock));

    // Observer: record the latest observed TTL for each record type.
    // The announcement packet (dns_type::any) contains PTR, SRV, A, and AAAA.
    // Key names: "ptr", "srv", "txt", "a", "aaaa".
    std::map<std::string, uint32_t> ttl_by_type;

    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        std::visit([&](const auto &r)
        {
            using T = std::decay_t<decltype(r)>;
            if constexpr (std::is_same_v<T, record_ptr>)
            {
                // Match service-type PTR (not meta-query _services._dns-sd._udp).
                if(r.name.find("_http._tcp") != dns_name::npos)
                    ttl_by_type["ptr"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_srv>)
            {
                if(r.name.find("pertypettl") != dns_name::npos)
                    ttl_by_type["srv"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_txt>)
            {
                if(r.name.find("pertypettl") != dns_name::npos)
                    ttl_by_type["txt"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_a>)
            {
                if(r.name.find("pertypettl") != dns_name::npos)
                    ttl_by_type["a"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_aaaa>)
            {
                if(r.name.find("pertypettl") != dns_name::npos)
                    ttl_by_type["aaaa"] = r.ttl;
            }
        }, rec);
    };

    auto obs = h.make_observer(std::move(obs_opts));
    obs.async_observe();
    h.executor.drain();

    // Drive server from probe through announce to live.
    // Announcements are sent via send_announcement() using dns_type::any,
    // which dispatches build_dns_response(m_info, dns_type::any, m_opts).
    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    // Each record type must be present in the observed announcements.
    REQUIRE(ttl_by_type.count("ptr") > 0);
    REQUIRE(ttl_by_type.count("srv") > 0);
    REQUIRE(ttl_by_type.count("a") > 0);
    REQUIRE(ttl_by_type.count("aaaa") > 0);

    // Verify each record type carries the configured TTL value.
    CHECK(ttl_by_type.at("ptr")  == 100u);
    CHECK(ttl_by_type.at("srv")  == 200u);
    CHECK(ttl_by_type.at("a")    == 400u);
    CHECK(ttl_by_type.at("aaaa") == 500u);

    // TXT: not present (service has empty txt_records; omitted from packet).
}

// ---------------------------------------------------------------------------
// TEST-11b: Goodbye uses TTL=0 for all record types
// ---------------------------------------------------------------------------
//
// Regardless of per-type TTL settings, stop() must send goodbye records with
// TTL=0 for all record types per RFC 6762 §11.3. The goodbye is built from a
// zeroed-out service_options copy, overriding any per-type TTL values.

TEST_CASE("Goodbye uses TTL=0 for all record types", "[local][ttl]")
{
    local_harness h;

    // Server with distinct non-zero per-type TTLs and goodbye enabled.
    service_options srv_opts = distinct_ttl_opts();
    srv_opts.send_goodbye = true;

    auto server = h.make_server(
        make_service("GbyeTtl._http._tcp.local.", "_http._tcp.local.",
                     "gbyettl.local.", 9090),
        std::move(srv_opts));

    // Observer: only capture records that arrive after stop() is called.
    std::map<std::string, uint32_t> goodbye_ttls;
    bool capture = false;

    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        if(!capture)
            return;
        std::visit([&](const auto &r)
        {
            using T = std::decay_t<decltype(r)>;
            if constexpr (std::is_same_v<T, record_ptr>)
            {
                if(r.name.find("_http._tcp") != dns_name::npos)
                    goodbye_ttls["ptr"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_srv>)
            {
                if(r.name.find("gbyettl") != dns_name::npos)
                    goodbye_ttls["srv"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_a>)
            {
                if(r.name.find("gbyettl") != dns_name::npos)
                    goodbye_ttls["a"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_aaaa>)
            {
                if(r.name.find("gbyettl") != dns_name::npos)
                    goodbye_ttls["aaaa"] = r.ttl;
            }
        }, rec);
    };

    auto obs = h.make_observer(std::move(obs_opts));
    obs.async_observe();
    h.executor.drain();

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    // Enable capture and trigger goodbye. stop() sends the goodbye packet
    // synchronously via the socket, which enqueues it on the bus.
    // h.executor.drain() delivers the queued packet to the observer.
    capture = true;
    server.stop();
    h.executor.drain();

    // Goodbye records (dns_type::any with all TTLs=0) must be present.
    REQUIRE(goodbye_ttls.count("ptr") > 0);
    REQUIRE(goodbye_ttls.count("srv") > 0);
    REQUIRE(goodbye_ttls.count("a") > 0);
    REQUIRE(goodbye_ttls.count("aaaa") > 0);

    // All goodbye TTLs must be zero regardless of per-type service_options settings.
    CHECK(goodbye_ttls.at("ptr")  == 0u);
    CHECK(goodbye_ttls.at("srv")  == 0u);
    CHECK(goodbye_ttls.at("a")    == 0u);
    CHECK(goodbye_ttls.at("aaaa") == 0u);
}

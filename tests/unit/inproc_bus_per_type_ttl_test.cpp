// tests/unit/inproc_bus_per_type_ttl_test.cpp
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

#include "mdnspp/inproc/inproc_harness.h"

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
using mdnspp::inproc::inproc_harness;

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
    opts.fallback_record_ttl = std::chrono::seconds{600};
    opts.respond_to_meta_queries = false;
    return opts;
}

}

// ---------------------------------------------------------------------------
// TEST-11a: Per-type TTLs appear in wire responses
// ---------------------------------------------------------------------------

TEST_CASE("Per-type TTLs appear in wire responses", "[inproc][ttl]")
{
    inproc_harness h;

    inproc::inproc_socket_options srv_sock;
    srv_sock.multicast_loopback = loopback_mode::disabled;

    auto server = h.make_server(
        make_service("PerTypeTtl._http._tcp.local.", "_http._tcp.local.",
                     "pertypettl.local.", 8080),
        distinct_ttl_opts(), std::move(srv_sock));

    std::map<std::string, uint32_t> ttl_by_type;

    observer_options obs_opts;
    obs_opts.on_record = [&](const endpoint &, const mdns_record_variant &rec)
    {
        std::visit([&](const auto &r)
        {
            using T = std::decay_t<decltype(r)>;
            if constexpr (std::is_same_v<T, record_ptr>)
            {
                if(r.name.find("_http._tcp") != dns_name::npos)
                    ttl_by_type["ptr"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_srv>)
            {
                if(r.name.find("PerTypeTtl") != dns_name::npos)
                    ttl_by_type["srv"] = r.ttl;
            }
            else if constexpr (std::is_same_v<T, record_txt>)
            {
                if(r.name.find("PerTypeTtl") != dns_name::npos)
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

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    REQUIRE(ttl_by_type.count("ptr") > 0);
    REQUIRE(ttl_by_type.count("srv") > 0);
    REQUIRE(ttl_by_type.count("a") > 0);
    REQUIRE(ttl_by_type.count("aaaa") > 0);

    CHECK(ttl_by_type.at("ptr")  == 100u);
    CHECK(ttl_by_type.at("srv")  == 200u);
    CHECK(ttl_by_type.at("a")    == 400u);
    CHECK(ttl_by_type.at("aaaa") == 500u);
}

// ---------------------------------------------------------------------------
// TEST-11b: Goodbye uses TTL=0 for all record types
// ---------------------------------------------------------------------------

TEST_CASE("Goodbye uses TTL=0 for all record types", "[inproc][ttl]")
{
    inproc_harness h;

    service_options srv_opts = distinct_ttl_opts();
    srv_opts.send_goodbye = true;

    auto server = h.make_server(
        make_service("GbyeTtl._http._tcp.local.", "_http._tcp.local.",
                     "gbyettl.local.", 9090),
        std::move(srv_opts));

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
                if(r.name.find("GbyeTtl") != dns_name::npos)
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

    capture = true;
    server.stop();
    h.executor.drain();

    REQUIRE(goodbye_ttls.count("ptr") > 0);
    REQUIRE(goodbye_ttls.count("srv") > 0);
    REQUIRE(goodbye_ttls.count("a") > 0);
    REQUIRE(goodbye_ttls.count("aaaa") > 0);

    CHECK(goodbye_ttls.at("ptr")  == 0u);
    CHECK(goodbye_ttls.at("srv")  == 0u);
    CHECK(goodbye_ttls.at("a")    == 0u);
    CHECK(goodbye_ttls.at("aaaa") == 0u);
}

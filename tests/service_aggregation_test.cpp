// tests/service_aggregation_test.cpp
// Pure unit tests for aggregate() — no mock policy, no networking, no DNS wire format.
// Constructs mdns_record_variant values directly and verifies resolved_service output.

#include "mdnspp/records.h"
#include "mdnspp/resolved_service.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace mdnspp;

static record_ptr make_ptr(std::string ptr_name)
{
    record_ptr r;
    r.name = "_http._tcp.local";
    r.ptr_name = std::move(ptr_name);
    return r;
}

static record_srv make_srv(std::string name, std::string srv_name, uint16_t port)
{
    record_srv r;
    r.name = std::move(name);
    r.srv_name = std::move(srv_name);
    r.port = port;
    return r;
}

static record_a make_a(std::string name, std::string address)
{
    record_a r;
    r.name = std::move(name);
    r.address_string = std::move(address);
    return r;
}

static record_aaaa make_aaaa(std::string name, std::string address)
{
    record_aaaa r;
    r.name = std::move(name);
    r.address_string = std::move(address);
    return r;
}

static record_txt make_txt(std::string name, std::vector<service_txt> entries)
{
    record_txt r;
    r.name = std::move(name);
    r.entries = std::move(entries);
    return r;
}

TEST_CASE("aggregate() with empty input returns empty vector", "[aggregate]")
{
    std::vector<mdns_record_variant> records;
    auto result = aggregate(records);
    REQUIRE(result.empty());
}

TEST_CASE("aggregate() with single PTR returns one entry with instance_name set", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].instance_name == "MyService._http._tcp.local");
    REQUIRE(result[0].hostname.empty());
    REQUIRE(result[0].port == 0);
    REQUIRE(result[0].txt_entries.empty());
    REQUIRE(result[0].ipv4_addresses.empty());
    REQUIRE(result[0].ipv6_addresses.empty());
}

TEST_CASE("aggregate() with PTR + SRV populates hostname and port", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 8080),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].instance_name == "MyService._http._tcp.local");
    REQUIRE(result[0].hostname == "myhost.local");
    REQUIRE(result[0].port == 8080);
}

TEST_CASE("aggregate() with PTR + SRV + A populates ipv4_addresses", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 8080),
        make_a("myhost.local", "192.168.1.1"),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].ipv4_addresses.size() == 1);
    REQUIRE(result[0].ipv4_addresses[0] == "192.168.1.1");
    REQUIRE(result[0].ipv6_addresses.empty());
}

TEST_CASE("aggregate() with PTR + SRV + AAAA populates ipv6_addresses", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 8080),
        make_aaaa("myhost.local", "fe80::1"),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].ipv6_addresses.size() == 1);
    REQUIRE(result[0].ipv6_addresses[0] == "fe80::1");
    REQUIRE(result[0].ipv4_addresses.empty());
}

TEST_CASE("aggregate() with PTR + TXT populates txt_entries", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_txt("MyService._http._tcp.local", {
                     service_txt{"path", "/api"},
                     service_txt{"version", "1"},
                 }),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].txt_entries.size() == 2);
    REQUIRE(result[0].txt_entries[0].key == "path");
    REQUIRE(result[0].txt_entries[0].value.has_value());
    REQUIRE(*result[0].txt_entries[0].value == "/api");
    REQUIRE(result[0].txt_entries[1].key == "version");
}

TEST_CASE("aggregate() with full set populates all fields", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 8080),
        make_txt("MyService._http._tcp.local", {service_txt{"k", "v"}}),
        make_a("myhost.local", "192.168.1.1"),
        make_aaaa("myhost.local", "fe80::1"),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    const auto &svc = result[0];
    REQUIRE(svc.instance_name == "MyService._http._tcp.local");
    REQUIRE(svc.hostname == "myhost.local");
    REQUIRE(svc.port == 8080);
    REQUIRE(svc.txt_entries.size() == 1);
    REQUIRE(svc.txt_entries[0].key == "k");
    REQUIRE(svc.ipv4_addresses.size() == 1);
    REQUIRE(svc.ipv4_addresses[0] == "192.168.1.1");
    REQUIRE(svc.ipv6_addresses.size() == 1);
    REQUIRE(svc.ipv6_addresses[0] == "fe80::1");
}

TEST_CASE("aggregate() A record arriving before SRV is still correlated (two-pass)", "[aggregate]")
{
    // A record comes BEFORE SRV — two-pass must still correlate it
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_a("myhost.local", "10.0.0.1"),
        // before SRV
        make_srv("MyService._http._tcp.local", "myhost.local", 9000),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].hostname == "myhost.local");
    REQUIRE(result[0].port == 9000);
    REQUIRE(result[0].ipv4_addresses.size() == 1);
    REQUIRE(result[0].ipv4_addresses[0] == "10.0.0.1");
}

TEST_CASE("aggregate() AAAA record arriving before SRV is still correlated (two-pass)", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_aaaa("myhost.local", "::1"),
        // before SRV
        make_srv("MyService._http._tcp.local", "myhost.local", 9000),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].ipv6_addresses.size() == 1);
    REQUIRE(result[0].ipv6_addresses[0] == "::1");
}

TEST_CASE("aggregate() deduplicates duplicate IPv4 addresses", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 80),
        make_a("myhost.local", "192.168.1.1"),
        make_a("myhost.local", "192.168.1.1"),
        // duplicate
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].ipv4_addresses.size() == 1);
    REQUIRE(result[0].ipv4_addresses[0] == "192.168.1.1");
}

TEST_CASE("aggregate() deduplicates duplicate IPv6 addresses", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 80),
        make_aaaa("myhost.local", "fe80::1"),
        make_aaaa("myhost.local", "fe80::1"),
        // duplicate
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].ipv6_addresses.size() == 1);
}

TEST_CASE("aggregate() deduplicates TXT entries by key (latest value wins)", "[aggregate]")
{
    // Two TXT records for the same instance — second TXT's key "path" should win
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_txt("MyService._http._tcp.local", {service_txt{"path", "/old"}}),
        make_txt("MyService._http._tcp.local", {service_txt{"path", "/new"}}),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    // Exactly one "path" entry, latest value wins
    auto path_count = std::ranges::count_if(result[0].txt_entries,
                                            [](const service_txt &e) { return e.key == "path"; });
    REQUIRE(path_count == 1);
    auto it = std::ranges::find_if(result[0].txt_entries,
                                   [](const service_txt &e) { return e.key == "path"; });
    REQUIRE(it != result[0].txt_entries.end());
    REQUIRE(it->value.has_value());
    REQUIRE(*it->value == "/new");
}

TEST_CASE("aggregate() second SRV for same instance overwrites hostname/port (latest wins)", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "old-host.local", 1111),
        make_srv("MyService._http._tcp.local", "new-host.local", 2222),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].hostname == "new-host.local");
    REQUIRE(result[0].port == 2222);
}

TEST_CASE("aggregate() handles two different services returning two entries", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("ServiceA._http._tcp.local"),
        make_ptr("ServiceB._http._tcp.local"),
        make_srv("ServiceA._http._tcp.local", "hosta.local", 80),
        make_srv("ServiceB._http._tcp.local", "hostb.local", 443),
        make_a("hosta.local", "10.0.0.1"),
        make_a("hostb.local", "10.0.0.2"),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 2);

    // Order not guaranteed — find by instance_name
    auto a_it = std::ranges::find_if(result,
                                     [](const resolved_service &s) { return s.instance_name == "ServiceA._http._tcp.local"; });
    auto b_it = std::ranges::find_if(result,
                                     [](const resolved_service &s) { return s.instance_name == "ServiceB._http._tcp.local"; });

    REQUIRE(a_it != result.end());
    REQUIRE(b_it != result.end());
    REQUIRE(a_it->hostname == "hosta.local");
    REQUIRE(a_it->port == 80);
    REQUIRE(a_it->ipv4_addresses.size() == 1);
    REQUIRE(a_it->ipv4_addresses[0] == "10.0.0.1");
    REQUIRE(b_it->hostname == "hostb.local");
    REQUIRE(b_it->port == 443);
    REQUIRE(b_it->ipv4_addresses.size() == 1);
    REQUIRE(b_it->ipv4_addresses[0] == "10.0.0.2");
}

TEST_CASE("aggregate() services sharing same hostname both get the A record", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("ServiceA._http._tcp.local"),
        make_ptr("ServiceB._http._tcp.local"),
        make_srv("ServiceA._http._tcp.local", "shared-host.local", 80),
        make_srv("ServiceB._http._tcp.local", "shared-host.local", 443),
        make_a("shared-host.local", "192.168.1.100"),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 2);
    for(const auto &svc : result)
    {
        REQUIRE(svc.ipv4_addresses.size() == 1);
        REQUIRE(svc.ipv4_addresses[0] == "192.168.1.100");
    }
}

TEST_CASE("aggregate() orphan A record (no matching SRV) does not create spurious entry", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 80),
        make_a("orphan-host.local", "10.0.0.99"),
        // no SRV points here
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].ipv4_addresses.empty());
}

TEST_CASE("aggregate() SRV without matching PTR does not create a resolved_service entry", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_srv("Orphan._http._tcp.local", "myhost.local", 80),
        make_a("myhost.local", "10.0.0.1"),
    };
    auto result = aggregate(records);
    REQUIRE(result.empty());
}

TEST_CASE("aggregate() span overload produces identical result", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 8080),
        make_a("myhost.local", "192.168.1.1"),
    };
    auto r1 = aggregate(records);
    auto r2 = aggregate(std::span<const mdns_record_variant>{records});
    REQUIRE(r1.size() == r2.size());
    REQUIRE(r1[0].instance_name == r2[0].instance_name);
    REQUIRE(r1[0].hostname == r2[0].hostname);
    REQUIRE(r1[0].port == r2[0].port);
    REQUIRE(r1[0].ipv4_addresses == r2[0].ipv4_addresses);
}

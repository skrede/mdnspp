#include "helpers.h"

#include "mdnspp/records.h"
#include "mdnspp/resolved_service.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>

using namespace mdnspp;

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
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_a("myhost.local", "10.0.0.1"),
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
        make_srv("MyService._http._tcp.local", "myhost.local", 9000),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].ipv6_addresses.size() == 1);
    REQUIRE(result[0].ipv6_addresses[0] == "::1");
}

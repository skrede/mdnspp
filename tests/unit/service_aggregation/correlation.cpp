#include "helpers.h"

#include "mdnspp/records.h"
#include "mdnspp/dns_name.h"
#include "mdnspp/resolved_service.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstdint>
#include <algorithm>
#include <string_view>

using namespace mdnspp;

namespace {

std::vector<resolved_service>::const_iterator find_instance(const std::vector<resolved_service> &services,
                                                            const dns_name &name)
{
    return std::ranges::find_if(services, [&name](const resolved_service &s) { return s.instance_name == name; });
}

void check_resolved(const resolved_service &svc, const dns_name &hostname, uint16_t port, std::string_view ipv4)
{
    REQUIRE(svc.hostname == hostname);
    REQUIRE(svc.port == port);
    REQUIRE(svc.ipv4_addresses.size() == 1);
    REQUIRE(svc.ipv4_addresses[0] == ipv4);
}

}

TEST_CASE("aggregate() deduplicates duplicate IPv4 addresses", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_srv("MyService._http._tcp.local", "myhost.local", 80),
        make_a("myhost.local", "192.168.1.1"),
        make_a("myhost.local", "192.168.1.1"),
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
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].ipv6_addresses.size() == 1);
}

TEST_CASE("aggregate() deduplicates TXT entries by key (latest value wins)", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("MyService._http._tcp.local"),
        make_txt("MyService._http._tcp.local", {service_txt{"path", "/old"}}),
        make_txt("MyService._http._tcp.local", {service_txt{"path", "/new"}}),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    auto is_path = [](const service_txt &e) { return e.key == "path"; };
    REQUIRE(std::ranges::count_if(result[0].txt_entries, is_path) == 1);
    auto it = std::ranges::find_if(result[0].txt_entries, is_path);
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

    // The result order is unspecified, so the services are looked up by instance name.
    auto a_it = find_instance(result, "ServiceA._http._tcp.local");
    auto b_it = find_instance(result, "ServiceB._http._tcp.local");
    REQUIRE(a_it != result.end());
    REQUIRE(b_it != result.end());
    check_resolved(*a_it, "hosta.local", 80, "10.0.0.1");
    check_resolved(*b_it, "hostb.local", 443, "10.0.0.2");
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

TEST_CASE("aggregate() const vector& convenience overload works", "[aggregate]")
{
    const std::vector<mdns_record_variant> records = {
        make_ptr("Svc._http._tcp.local"),
        make_srv("Svc._http._tcp.local", "host.local", 80),
        make_a("host.local", "1.2.3.4"),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].instance_name == "Svc._http._tcp.local");
    REQUIRE(result[0].ipv4_addresses.size() == 1);
}

TEST_CASE("aggregate() duplicate PTR records for same instance yield single entry", "[aggregate]")
{
    std::vector<mdns_record_variant> records = {
        make_ptr("DupService._http._tcp.local"),
        make_ptr("DupService._http._tcp.local"),
        make_srv("DupService._http._tcp.local", "duphost.local", 9090),
        make_a("duphost.local", "10.0.0.5"),
    };
    auto result = aggregate(records);
    REQUIRE(result.size() == 1);
    REQUIRE(result[0].instance_name == "DupService._http._tcp.local");
    REQUIRE(result[0].port == 9090);
}

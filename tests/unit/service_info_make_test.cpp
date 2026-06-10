// tests/service_info_make_test.cpp
//
// service_info::make() — service type normalization, RFC 1035 §5.1 instance
// label escaping, hostname derivation and the auto_address contract.

#include "mdnspp/dns_name.h"
#include "mdnspp/mdns_error.h"
#include "mdnspp/service_info.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <optional>
#include <string_view>

using namespace mdnspp;

TEST_CASE("make derives the full service type from a bare type", "[service_info][make]")
{
    auto info = service_info::make("MyApp", "_http._tcp", 8080,
                                   {.hostname = "myhost"});
    REQUIRE(info.has_value());
    REQUIRE(info->service_type == "_http._tcp.local.");
    REQUIRE(info->service_name == "MyApp._http._tcp.local.");
    REQUIRE(info->hostname == "myhost.local.");
    REQUIRE(info->port == 8080);
}

TEST_CASE("make accepts the full service type with and without trailing dot", "[service_info][make]")
{
    for(const char *type : {"_http._tcp.local", "_http._tcp.local.", "_http._tcp."})
    {
        auto info = service_info::make("MyApp", type, 8080, {.hostname = "myhost"});
        REQUIRE(info.has_value());
        REQUIRE(info->service_type == "_http._tcp.local.");
        REQUIRE(info->service_name == "MyApp._http._tcp.local.");
    }
}

TEST_CASE("make escapes dots and backslashes in the instance label", "[service_info][make]")
{
    auto info = service_info::make("Dr. Smith", "_http._tcp", 80, {.hostname = "myhost"});
    REQUIRE(info.has_value());
    // RFC 6763 §4.3: the dot is content, not a label separator.
    REQUIRE(info->service_name.str() == "Dr\\. Smith._http._tcp.local.");

    auto with_backslash = service_info::make("a\\b", "_http._tcp", 80, {.hostname = "myhost"});
    REQUIRE(with_backslash.has_value());
    REQUIRE(with_backslash->service_name.str() == "a\\\\b._http._tcp.local.");
}

TEST_CASE("make preserves UTF-8 instance label bytes", "[service_info][make]")
{
    auto info = service_info::make("Caff\xc3\xa8 Web", "_http._tcp", 80, {.hostname = "myhost"});
    REQUIRE(info.has_value());
    REQUIRE(info->service_name.str() == "Caff\xc3\xa8 Web._http._tcp.local.");
}

TEST_CASE("make rejects a structurally invalid service type", "[service_info][make]")
{
    auto missing_protocol = service_info::make("MyApp", "_http", 80);
    REQUIRE_FALSE(missing_protocol.has_value());
    REQUIRE(missing_protocol.error() == mdns_error::invalid_name);

    auto empty_type = service_info::make("MyApp", "", 80);
    REQUIRE_FALSE(empty_type.has_value());
    REQUIRE(empty_type.error() == mdns_error::invalid_name);
}

TEST_CASE("make rejects an empty or oversize instance label", "[service_info][make]")
{
    auto empty_instance = service_info::make("", "_http._tcp", 80);
    REQUIRE_FALSE(empty_instance.has_value());
    REQUIRE(empty_instance.error() == mdns_error::invalid_name);

    auto oversize = service_info::make(std::string(64, 'a'), "_http._tcp", 80);
    REQUIRE_FALSE(oversize.has_value());
    REQUIRE(oversize.error() == mdns_error::invalid_name);
}

TEST_CASE("make rejects port 0", "[service_info][make]")
{
    auto info = service_info::make("MyApp", "_http._tcp", 0);
    REQUIRE_FALSE(info.has_value());
    REQUIRE(info.error() == mdns_error::invalid_argument);
}

TEST_CASE("make normalizes the hostname override", "[service_info][make]")
{
    auto bare = service_info::make("A", "_http._tcp", 80, {.hostname = "myhost"});
    REQUIRE(bare.has_value());
    REQUIRE(bare->hostname == "myhost.local.");

    auto suffixed = service_info::make("A", "_http._tcp", 80, {.hostname = "myhost.local"});
    REQUIRE(suffixed.has_value());
    REQUIRE(suffixed->hostname == "myhost.local.");

    auto fqdn = service_info::make("A", "_http._tcp", 80, {.hostname = "myhost.local."});
    REQUIRE(fqdn.has_value());
    REQUIRE(fqdn->hostname == "myhost.local.");

    // ASCII case-insensitive suffix detection; original case is preserved.
    auto cased = service_info::make("A", "_http._tcp", 80, {.hostname = "MyHost.LOCAL"});
    REQUIRE(cased.has_value());
    REQUIRE(cased->hostname.str() == "MyHost.LOCAL.");
    REQUIRE(cased->hostname == "myhost.local.");

    auto empty_host = service_info::make("A", "_http._tcp", 80, {.hostname = ""});
    REQUIRE_FALSE(empty_host.has_value());
    REQUIRE(empty_host.error() == mdns_error::invalid_name);
}

TEST_CASE("make derives the hostname from the OS host name", "[service_info][make]")
{
    auto info = service_info::make("MyApp", "_http._tcp", 8080);
    REQUIRE(info.has_value());
    REQUIRE_FALSE(info->hostname.empty());

    const std::string &host = info->hostname.str();
    constexpr std::string_view suffix = ".local.";
    REQUIRE(host.size() > suffix.size());
    REQUIRE(host.compare(host.size() - suffix.size(), suffix.size(), suffix) == 0);
    REQUIRE(dns_name::parse(host).has_value());
}

TEST_CASE("make enables auto_address only for unset address fields", "[service_info][make]")
{
    auto both_unset = service_info::make("A", "_http._tcp", 80, {.hostname = "h"});
    REQUIRE(both_unset.has_value());
    REQUIRE(both_unset->auto_address);
    REQUIRE_FALSE(both_unset->address_ipv4.has_value());
    REQUIRE_FALSE(both_unset->address_ipv6.has_value());

    auto ipv4_set = service_info::make("A", "_http._tcp", 80,
                                       {.hostname = "h", .address_ipv4 = "192.168.1.10"});
    REQUIRE(ipv4_set.has_value());
    REQUIRE(ipv4_set->auto_address); // IPv6 is still auto-detected
    REQUIRE(ipv4_set->address_ipv4 == "192.168.1.10");

    auto both_set = service_info::make("A", "_http._tcp", 80,
                                       {.hostname = "h",
                                        .address_ipv4 = "192.168.1.10",
                                        .address_ipv6 = "fe80::1"});
    REQUIRE(both_set.has_value());
    REQUIRE_FALSE(both_set->auto_address);
}

TEST_CASE("make with advertise_addresses false clears addresses and disables auto_address", "[service_info][make]")
{
    auto info = service_info::make("A", "_http._tcp", 80,
                                   {.hostname = "h",
                                    .address_ipv4 = "192.168.1.10",
                                    .address_ipv6 = "fe80::1",
                                    .advertise_addresses = false});
    REQUIRE(info.has_value());
    REQUIRE_FALSE(info->address_ipv4.has_value());
    REQUIRE_FALSE(info->address_ipv6.has_value());
    REQUIRE_FALSE(info->auto_address);
}

TEST_CASE("make forwards priority, weight, txt_records and subtypes", "[service_info][make]")
{
    auto info = service_info::make("A", "_http._tcp", 80,
                                   {.hostname = "h",
                                    .priority = 10,
                                    .weight = 20,
                                    .txt_records = {{"path", "/api"}, {"flag", std::nullopt}},
                                    .subtypes = {"_printer"}});
    REQUIRE(info.has_value());
    REQUIRE(info->priority == 10);
    REQUIRE(info->weight == 20);
    REQUIRE(info->txt_records.size() == 2);
    REQUIRE(info->txt_records[0].key == "path");
    REQUIRE(info->subtypes == std::vector<std::string>{"_printer"});
}

TEST_CASE("aggregate-built service_info keeps auto_address disabled", "[service_info][make]")
{
    service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname = "myhost.local.",
        .port = 8080,
        .address_ipv4 = {},
        .address_ipv6 = {},
        .txt_records = {},
        .subtypes = {},
    };
    REQUIRE_FALSE(info.auto_address);
}

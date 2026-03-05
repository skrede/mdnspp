#include "mdnspp/records.h"

#include <catch2/catch_test_macros.hpp>

#include <sstream>

using namespace mdnspp;

TEST_CASE("record_ptr streams correctly", "[records][operator<<]")
{
    record_ptr r{
        .name = "_http._tcp.local.",
        .ttl = 120,
        .rclass = dns_class::in,
        .length = 42,
        .sender_address = "192.168.1.10",
        .ptr_name = "MyService._http._tcp.local.",
    };

    std::ostringstream os;
    os << r;

    const auto s = os.str();
    REQUIRE(s.contains("192.168.1.10"));
    REQUIRE(s.contains("PTR"));
    REQUIRE(s.contains("_http._tcp.local."));
    REQUIRE(s.contains("MyService._http._tcp.local."));
    REQUIRE(s.contains("120"));
}

TEST_CASE("record_srv streams correctly", "[records][operator<<]")
{
    record_srv r{
        .name = "MyService._http._tcp.local.",
        .ttl = 60,
        .rclass = dns_class::in,
        .length = 30,
        .sender_address = "10.0.0.1",
        .port = 8080,
        .weight = 0,
        .priority = 0,
        .srv_name = "myhost.local.",
    };

    std::ostringstream os;
    os << r;

    const auto s = os.str();
    REQUIRE(s.contains("10.0.0.1"));
    REQUIRE(s.contains("SRV"));
    REQUIRE(s.contains("myhost.local."));
    REQUIRE(s.contains("8080"));
}

TEST_CASE("record_a streams correctly", "[records][operator<<]")
{
    record_a r{
        .name = "myhost.local.",
        .ttl = 300,
        .rclass = dns_class::in,
        .length = 4,
        .sender_address = "192.168.1.10",
        .address_string = "192.168.1.42",
    };

    std::ostringstream os;
    os << r;

    const auto s = os.str();
    REQUIRE(s.contains("192.168.1.10"));
    REQUIRE(s.contains("A"));
    REQUIRE(s.contains("192.168.1.42"));
    REQUIRE(s.contains("300"));
}

TEST_CASE("record_aaaa streams correctly", "[records][operator<<]")
{
    record_aaaa r{
        .name = "myhost.local.",
        .ttl = 300,
        .rclass = dns_class::in,
        .length = 16,
        .sender_address = "fe80::1",
        .address_string = "fe80::42",
    };

    std::ostringstream os;
    os << r;

    const auto s = os.str();
    REQUIRE(s.contains("fe80::1"));
    REQUIRE(s.contains("AAAA"));
    REQUIRE(s.contains("fe80::42"));
    REQUIRE(s.contains("300"));
}

TEST_CASE("record_txt streams correctly", "[records][operator<<]")
{
    record_txt r{
        .name = "MyService._http._tcp.local.",
        .ttl = 4500,
        .rclass = dns_class::in,
        .length = 50,
        .sender_address = "10.0.0.5",
        .entries = {
            {.key = "path", .value = "/api"},
            {.key = "flag", .value = std::nullopt},
        },
    };

    std::ostringstream os;
    os << r;

    const auto s = os.str();
    REQUIRE(s.contains("10.0.0.5"));
    REQUIRE(s.contains("TXT"));
    REQUIRE(s.contains("path=/api"));
    REQUIRE(s.contains("flag"));
    REQUIRE_FALSE(s.contains("flag="));
    REQUIRE(s.contains("4500"));
}

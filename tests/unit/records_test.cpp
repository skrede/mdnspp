#include "mdnspp/records.h"

#include <catch2/catch_test_macros.hpp>

#include <sstream>
#include <string>
#include <string_view>

using namespace mdnspp;

// std::string::contains is C++23; the project targets C++20.
static bool contains(const std::string &s, std::string_view needle)
{
    return s.find(needle) != std::string::npos;
}

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
    REQUIRE(contains(s, "192.168.1.10"));
    REQUIRE(contains(s, "PTR"));
    REQUIRE(contains(s, "_http._tcp.local."));
    REQUIRE(contains(s, "myservice._http._tcp.local."));
    REQUIRE(contains(s, "120"));
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
    REQUIRE(contains(s, "10.0.0.1"));
    REQUIRE(contains(s, "SRV"));
    REQUIRE(contains(s, "myhost.local."));
    REQUIRE(contains(s, "8080"));
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
    REQUIRE(contains(s, "192.168.1.10"));
    REQUIRE(contains(s, "A"));
    REQUIRE(contains(s, "192.168.1.42"));
    REQUIRE(contains(s, "300"));
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
    REQUIRE(contains(s, "fe80::1"));
    REQUIRE(contains(s, "AAAA"));
    REQUIRE(contains(s, "fe80::42"));
    REQUIRE(contains(s, "300"));
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
    REQUIRE(contains(s, "10.0.0.5"));
    REQUIRE(contains(s, "TXT"));
    REQUIRE(contains(s, "path=/api"));
    REQUIRE(contains(s, "flag"));
    REQUIRE_FALSE(contains(s, "flag="));
    REQUIRE(contains(s, "4500"));
}

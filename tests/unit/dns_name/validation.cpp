#include "mdnspp/dns_name.h"
#include "mdnspp/mdns_error.h"

#include <catch2/catch_test_macros.hpp>

#include <string>

using mdnspp::dns_name;

namespace {

void check_escaped_dot()
{
    GIVEN("an instance label containing a dot (RFC 6763 section 4.3)")
    {
        dns_name n("Dr\\. Smith._http._tcp.local");
        THEN("the escaped dot is preserved in canonical form")
        {
            REQUIRE(n.str() == "Dr\\. Smith._http._tcp.local.");
        }
        THEN("the escaped dot does not equal a label separator")
        {
            REQUIRE(n != dns_name("Dr. Smith._http._tcp.local."));
        }
    }
}

void check_decimal_escape()
{
    GIVEN("a \\DDD decimal escape")
    {
        THEN("\\068 canonicalizes to the printable byte it denotes")
        {
            REQUIRE(dns_name("\\068r.local.") == dns_name("Dr.local."));
            REQUIRE(dns_name("\\068r.local.").str() == "Dr.local.");
        }
        THEN("a non-printable byte stays in \\DDD form")
        {
            REQUIRE(dns_name("a\\009b.local.").str() == "a\\009b.local.");
        }
    }
}

void check_empty_labels()
{
    GIVEN("a name with an empty label")
    {
        THEN("a..b.local normalizes to the empty name")
        {
            REQUIRE(dns_name("a..b.local").empty());
        }
        THEN("a leading dot normalizes to the empty name")
        {
            REQUIRE(dns_name(".a.local").empty());
        }
    }
}

}

SCENARIO("dns_name handles RFC 1035 section 5.1 escapes", "[dns_name][escaping]")
{
    check_escaped_dot();
    check_decimal_escape();

    GIVEN("invalid escape sequences")
    {
        THEN("a dangling backslash normalizes to the empty name")
        {
            REQUIRE(dns_name("abc\\").empty());
        }
        THEN("a truncated \\DDD escape normalizes to the empty name")
        {
            REQUIRE(dns_name("a\\12.local").empty());
        }
        THEN("a \\DDD value above 255 normalizes to the empty name")
        {
            REQUIRE(dns_name("a\\999.local").empty());
        }
    }
}

SCENARIO("dns_name rejects empty labels and oversize labels and names", "[dns_name][validation]")
{
    check_empty_labels();

    GIVEN("a 64-byte label")
    {
        std::string name = std::string(64, 'a') + ".local";
        THEN("it normalizes to the empty name")
        {
            REQUIRE(dns_name(name).empty());
        }
    }

    GIVEN("a name exceeding 255 wire bytes")
    {
        std::string name = std::string(63, 'a') + "." + std::string(63, 'b') + "."
                         + std::string(63, 'c') + "." + std::string(63, 'd');
        THEN("it normalizes to the empty name")
        {
            REQUIRE(dns_name(name).empty());
        }
    }
}

SCENARIO("dns_name::parse reports invalid_name on the checked path", "[dns_name][parse]")
{
    GIVEN("a valid presentation name")
    {
        auto result = dns_name::parse("MyHost.local");
        THEN("parse succeeds with the canonical form")
        {
            REQUIRE(result.has_value());
            REQUIRE(result->str() == "MyHost.local.");
        }
    }

    GIVEN("an invalid presentation name")
    {
        auto result = dns_name::parse("a..b.local");
        THEN("parse fails with mdns_error::invalid_name")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_name);
        }
    }
}

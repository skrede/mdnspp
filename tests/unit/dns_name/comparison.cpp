#include "mdnspp/dns_name.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <compare>
#include <sstream>
#include <unordered_map>

using mdnspp::dns_name;

namespace {

std::string stream_str(const dns_name &n)
{
    std::ostringstream oss;
    oss << n;
    return oss.str();
}

void check_case_only_difference()
{
    GIVEN("two names that differ only in ASCII case")
    {
        dns_name a("_http._tcp.local.");
        dns_name b("_HTTP._TCP.LOCAL.");
        THEN("they compare equal")
        {
            REQUIRE(a == b);
        }
        THEN("their comparison keys are identical")
        {
            REQUIRE(a.comparison_key() == b.comparison_key());
        }
    }
}

void check_high_byte_difference()
{
    GIVEN("two names that differ in a byte above 0x7F")
    {
        // 0xC3 0x89 (U+00C9) vs 0xC3 0xA9 (U+00E9): folding must not touch
        // bytes >= 0x80, so these are distinct names.
        dns_name a("Caf\xc3\x89.local.");
        dns_name b("Caf\xc3\xa9.local.");
        THEN("they compare unequal")
        {
            REQUIRE(a != b);
        }
    }
}

void check_unordered_map_lookup()
{
    GIVEN("an unordered_map keyed on dns_name")
    {
        std::unordered_map<dns_name, int> m;
        WHEN("a key is inserted using an unnormalized form")
        {
            m[dns_name("_http._tcp.local")] = 42;
            THEN("lookup via the normalized form succeeds")
            {
                auto it = m.find(dns_name("_HTTP._TCP.LOCAL."));
                REQUIRE(it != m.end());
                REQUIRE(it->second == 42);
            }
        }
    }
}

}

SCENARIO("dns_name equality is ASCII-case-insensitive (RFC 6762 section 16)", "[dns_name][comparison]")
{
    check_case_only_difference();
    check_high_byte_difference();

    GIVEN("a name without trailing dot and the same name with trailing dot")
    {
        dns_name a("_http._tcp.local");
        dns_name b("_http._tcp.local.");
        THEN("they compare equal after normalization")
        {
            REQUIRE(a == b);
        }
    }

    GIVEN("two distinct names")
    {
        dns_name a("a.local.");
        dns_name b("b.local.");
        THEN("they compare unequal")
        {
            REQUIRE(a != b);
        }
    }
}

SCENARIO("dns_name supports three-way comparison via operator<=>", "[dns_name][comparison]")
{
    GIVEN("two distinct names in lexicographic order")
    {
        dns_name a("a.local.");
        dns_name b("b.local.");
        THEN("a < b")
        {
            REQUIRE(a < b);
        }
        THEN("b > a")
        {
            REQUIRE(b > a);
        }
    }

    GIVEN("two equal names")
    {
        dns_name a("test.local.");
        dns_name b("test.local.");
        THEN("a <=> b is equal")
        {
            REQUIRE((a <=> b) == std::strong_ordering::equal);
        }
    }
}

SCENARIO("dns_name is hashable and usable as unordered_map key", "[dns_name][hash]")
{
    GIVEN("two equal dns_name values")
    {
        dns_name a("_http._tcp.local.");
        dns_name b("_HTTP._TCP.LOCAL.");
        THEN("their hashes are equal")
        {
            REQUIRE(std::hash<dns_name>{}(a) == std::hash<dns_name>{}(b));
        }
    }

    check_unordered_map_lookup();
}

SCENARIO("dns_name streams its normalized value via operator<<", "[dns_name][operator<<]")
{
    GIVEN("a dns_name constructed from a mixed-case unnormalized string")
    {
        dns_name n("_HTTP._TCP.local");
        WHEN("streamed to an ostream")
        {
            THEN("the output is the case-preserved FQDN")
            {
                REQUIRE(stream_str(n) == "_HTTP._TCP.local.");
            }
        }
    }

    GIVEN("a default-constructed (empty) dns_name")
    {
        dns_name n;
        WHEN("streamed to an ostream")
        {
            THEN("the output is an empty string")
            {
                REQUIRE(stream_str(n).empty());
            }
        }
    }
}

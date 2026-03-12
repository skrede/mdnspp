// tests/dns_name_test.cpp

#include "mdnspp/dns_name.h"

#include <catch2/catch_test_macros.hpp>

#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>

using mdnspp::dns_name;

static std::string stream_str(const dns_name &n)
{
    std::ostringstream oss;
    oss << n;
    return oss.str();
}

SCENARIO("dns_name appends trailing dot when absent", "[dns_name][normalization]")
{
    GIVEN("a name without a trailing dot")
    {
        WHEN("constructed from a plain label string")
        {
            THEN("_http._tcp.local gains a trailing dot")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("_http._tcp.local")) == "_http._tcp.local.");
            }
            THEN("a single-label name gains a trailing dot")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("local")) == "local.");
            }
        }
    }

    GIVEN("a name that already has a trailing dot")
    {
        WHEN("constructed from an FQDN string")
        {
            THEN("_http._tcp.local. keeps its trailing dot (idempotent)")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("_http._tcp.local.")) == "_http._tcp.local.");
            }
        }
    }
}

SCENARIO("dns_name lowercases all ASCII characters on construction", "[dns_name][normalization]")
{
    GIVEN("a mixed-case DNS name")
    {
        WHEN("constructed from an uppercase string")
        {
            THEN("_HTTP._TCP.local. is stored as _http._tcp.local.")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("_HTTP._TCP.local.")) == "_http._tcp.local.");
            }
            THEN("MyHost.local. is stored as myhost.local.")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("MyHost.local.")) == "myhost.local.");
            }
        }
    }

    GIVEN("a name with mixed case and no trailing dot")
    {
        WHEN("constructed from _HTTP._TCP.local without trailing dot")
        {
            THEN("the result is _http._tcp.local. — lowercased and dot appended")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("_HTTP._TCP.local")) == "_http._tcp.local.");
            }
        }
    }
}

SCENARIO("dns_name preserves empty as empty (root label)", "[dns_name][normalization][edge]")
{
    GIVEN("an empty string_view")
    {
        WHEN("constructed from an empty string")
        {
            THEN("the result is empty — no trailing dot for the root label")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("")) == "");
            }
            THEN("empty() returns true")
            {
                REQUIRE(dns_name("").empty());
            }
        }
    }

    GIVEN("a non-empty name")
    {
        WHEN("constructed from a non-empty string")
        {
            THEN("empty() returns false")
            {
                REQUIRE_FALSE(dns_name("x.").empty());
            }
        }
    }
}

SCENARIO("dns_name default-constructs to an empty name", "[dns_name][construction]")
{
    GIVEN("a default-constructed dns_name")
    {
        dns_name n;
        THEN("it is empty")
        {
            REQUIRE(n.empty());
        }
        THEN("it converts to an empty string_view")
        {
            REQUIRE(static_cast<std::string_view>(n) == "");
        }
    }
}

SCENARIO("dns_name supports implicit construction from std::string_view", "[dns_name][conversion]")
{
    GIVEN("a std::string_view value")
    {
        std::string_view sv = "test.local";
        WHEN("assigned to a dns_name via implicit construction")
        {
            dns_name n = sv;
            THEN("the result is normalized")
            {
                REQUIRE(static_cast<std::string_view>(n) == "test.local.");
            }
        }
    }
}

SCENARIO("dns_name exposes normalized value via str()", "[dns_name][conversion]")
{
    GIVEN("a dns_name constructed from a mixed-case string")
    {
        dns_name n("_HTTP._TCP.local");
        WHEN("str() is called")
        {
            THEN("it returns the normalized std::string with trailing dot")
            {
                REQUIRE(n.str() == "_http._tcp.local.");
            }
        }
    }
}

SCENARIO("dns_name equality is based on normalized value", "[dns_name][comparison]")
{
    GIVEN("two names that differ only in case")
    {
        dns_name a("_http._tcp.local.");
        dns_name b("_HTTP._TCP.LOCAL.");
        THEN("they compare equal")
        {
            REQUIRE(a == b);
        }
    }

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

SCENARIO("dns_name streams its normalized value via operator<<", "[dns_name][operator<<]")
{
    GIVEN("a dns_name constructed from a mixed-case unnormalized string")
    {
        dns_name n("_HTTP._TCP.local");
        WHEN("streamed to an ostream")
        {
            THEN("the output is the normalized FQDN")
            {
                REQUIRE(stream_str(n) == "_http._tcp.local.");
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

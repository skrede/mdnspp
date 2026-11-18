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

SCENARIO("dns_name preserves original byte case on construction", "[dns_name][normalization]")
{
    GIVEN("a mixed-case DNS name")
    {
        WHEN("constructed from an uppercase string")
        {
            THEN("_HTTP._TCP.local. is stored unaltered (RFC 6763 section 4.1)")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("_HTTP._TCP.local.")) == "_HTTP._TCP.local.");
            }
            THEN("MyHost.local. keeps its case")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("MyHost.local.")) == "MyHost.local.");
            }
        }
    }

    GIVEN("a name with mixed case and no trailing dot")
    {
        WHEN("constructed from _HTTP._TCP.local without trailing dot")
        {
            THEN("only the trailing dot is appended")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("_HTTP._TCP.local")) == "_HTTP._TCP.local.");
            }
        }
    }

    GIVEN("a name containing UTF-8 bytes above 0x7F")
    {
        WHEN("constructed from a UTF-8 instance name")
        {
            THEN("the bytes are stored verbatim")
            {
                REQUIRE(static_cast<std::string_view>(dns_name("Caf\xc3\xa9._http._tcp.local."))
                        == "Caf\xc3\xa9._http._tcp.local.");
            }
        }
    }
}

SCENARIO("dns_name handles RFC 1035 section 5.1 escapes", "[dns_name][escaping]")
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
            THEN("it returns the case-preserved std::string with trailing dot")
            {
                REQUIRE(n.str() == "_HTTP._TCP.local.");
            }
        }
    }
}

SCENARIO("dns_name equality is ASCII-case-insensitive (RFC 6762 section 16)", "[dns_name][comparison]")
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

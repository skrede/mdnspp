#include "mdnspp/dns_name.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>

using mdnspp::dns_name;

namespace {

void check_plain_names_gain_dot()
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
}

void check_mixed_case_kept()
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
}

void check_dot_appended_and_utf8_kept()
{
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

void check_empty_stays_empty()
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
}

}

SCENARIO("dns_name appends trailing dot when absent", "[dns_name][normalization]")
{
    check_plain_names_gain_dot();

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
    check_mixed_case_kept();
    check_dot_appended_and_utf8_kept();
}

SCENARIO("dns_name preserves empty as empty (root label)", "[dns_name][normalization][edge]")
{
    check_empty_stays_empty();

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

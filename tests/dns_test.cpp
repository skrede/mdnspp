// tests/dns_test.cpp

#include "mdnspp/dns.h"

#include <catch2/catch_test_macros.hpp>

#include <sstream>

using mdnspp::dns_type;
using mdnspp::dns_class;

static std::string stream_str(dns_type t)
{
    std::ostringstream oss;
    oss << t;
    return oss.str();
}

static std::string stream_str(dns_class c)
{
    std::ostringstream oss;
    oss << c;
    return oss.str();
}

SCENARIO("dns_type streams known values as plain uppercase names", "[dns][dns_type][operator<<]")
{
    GIVEN("a known dns_type enumerator")
    {
        WHEN("streamed to an ostream")
        {
            THEN("dns_type::none streams as 'none'")
            {
                REQUIRE(stream_str(dns_type::none) == "none");
            }
            THEN("dns_type::a streams as 'A'")
            {
                REQUIRE(stream_str(dns_type::a) == "A");
            }
            THEN("dns_type::ptr streams as 'PTR'")
            {
                REQUIRE(stream_str(dns_type::ptr) == "PTR");
            }
            THEN("dns_type::txt streams as 'TXT'")
            {
                REQUIRE(stream_str(dns_type::txt) == "TXT");
            }
            THEN("dns_type::aaaa streams as 'AAAA'")
            {
                REQUIRE(stream_str(dns_type::aaaa) == "AAAA");
            }
            THEN("dns_type::srv streams as 'SRV'")
            {
                REQUIRE(stream_str(dns_type::srv) == "SRV");
            }
            THEN("dns_type::any streams as 'ANY'")
            {
                REQUIRE(stream_str(dns_type::any) == "ANY");
            }
        }
    }
}

SCENARIO("dns_type streams out-of-range values as 'unknown(N)'", "[dns][dns_type][operator<<]")
{
    GIVEN("a dns_type value not matching any named enumerator")
    {
        WHEN("streamed to an ostream")
        {
            THEN("it formats as 'unknown(N)' where N is the underlying integer")
            {
                REQUIRE(stream_str(static_cast<dns_type>(99)) == "unknown(99)");
            }
        }
    }
}

SCENARIO("dns_class streams known values as plain uppercase names", "[dns][dns_class][operator<<]")
{
    GIVEN("a known dns_class enumerator")
    {
        WHEN("streamed to an ostream")
        {
            THEN("dns_class::none streams as 'none'")
            {
                REQUIRE(stream_str(dns_class::none) == "none");
            }
            THEN("dns_class::in streams as 'IN'")
            {
                REQUIRE(stream_str(dns_class::in) == "IN");
            }
        }
    }
}

SCENARIO("dns_class streams out-of-range values as 'unknown(N)'", "[dns][dns_class][operator<<]")
{
    GIVEN("a dns_class value not matching any named enumerator")
    {
        WHEN("streamed to an ostream")
        {
            THEN("it formats as 'unknown(N)' where N is the underlying integer")
            {
                REQUIRE(stream_str(static_cast<dns_class>(42)) == "unknown(42)");
            }
        }
    }
}

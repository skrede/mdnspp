// tests/endpoint_test.cpp
// Tests for endpoint three-way comparison operators (ERG-03).

#include "mdnspp/endpoint.h"

#include <catch2/catch_test_macros.hpp>

using mdnspp::endpoint;

SCENARIO("endpoint equality comparison", "[endpoint][operator==]")
{
    GIVEN("two endpoints with identical address and port")
    {
        const endpoint a{"192.168.1.1", 5353};
        const endpoint b{"192.168.1.1", 5353};

        WHEN("compared with operator==")
        {
            THEN("they compare equal")
            {
                REQUIRE(a == b);
            }
        }
    }

    GIVEN("two endpoints with different addresses")
    {
        const endpoint a{"192.168.1.1", 80};
        const endpoint b{"192.168.1.2", 80};

        WHEN("compared with operator==")
        {
            THEN("they do not compare equal")
            {
                REQUIRE(a != b);
            }
        }
    }
}

SCENARIO("endpoint ordering by address", "[endpoint][operator<=>]")
{
    GIVEN("two endpoints where the first address is lexicographically less than the second")
    {
        const endpoint a{"a.local", 80};
        const endpoint b{"b.local", 80};

        WHEN("compared with relational operators")
        {
            THEN("a < b")
            {
                REQUIRE(a < b);
            }
            THEN("b > a")
            {
                REQUIRE(b > a);
            }
            THEN("a <= b")
            {
                REQUIRE(a <= b);
            }
            THEN("b >= a")
            {
                REQUIRE(b >= a);
            }
        }
    }
}

SCENARIO("endpoint ordering by port when addresses are equal", "[endpoint][operator<=>]")
{
    GIVEN("two endpoints with the same address but different ports")
    {
        const endpoint a{"host.local", 80};
        const endpoint b{"host.local", 5353};

        WHEN("compared with relational operators")
        {
            THEN("a < b (80 < 5353)")
            {
                REQUIRE(a < b);
            }
            THEN("b > a")
            {
                REQUIRE(b > a);
            }
        }
    }
}

SCENARIO("endpoint address takes precedence over port in ordering", "[endpoint][operator<=>]")
{
    GIVEN("endpoint{b, 1} and endpoint{a, 9999} where address 'b' > address 'a'")
    {
        const endpoint hi_addr{"b.local", 1};
        const endpoint lo_addr{"a.local", 9999};

        WHEN("compared with relational operators")
        {
            THEN("hi_addr > lo_addr because 'b' > 'a' despite lower port")
            {
                REQUIRE(hi_addr > lo_addr);
            }
            THEN("lo_addr < hi_addr")
            {
                REQUIRE(lo_addr < hi_addr);
            }
        }
    }
}

SCENARIO("endpoint self-comparison with <=, >=", "[endpoint][operator<=>]")
{
    GIVEN("a single endpoint")
    {
        const endpoint ep{"host.local", 5353};

        WHEN("compared to itself")
        {
            THEN("it is <= itself")
            {
                REQUIRE(ep <= ep);
            }
            THEN("it is >= itself")
            {
                REQUIRE(ep >= ep);
            }
        }
    }
}

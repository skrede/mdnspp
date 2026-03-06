// tests/mdns_util_test.cpp
// Unit tests for ip_address_to_string — IPv4 and IPv6 formatting, edge cases.

#include "mdnspp/detail/mdns_util.h"

#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>

using mdnspp::ip_address_to_string;

SCENARIO("ip_address_to_string formats sockaddr_in6 with :: compression", "[mdns_util][ipv6]")
{
    GIVEN("a sockaddr_in6 containing ::1 with port = 0")
    {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = 0;
        // ::1 = 15 zero bytes followed by 0x01
        std::memset(addr.sin6_addr.s6_addr, 0, 16);
        addr.sin6_addr.s6_addr[15] = 1;

        WHEN("ip_address_to_string is called")
        {
            auto result = ip_address_to_string(addr);

            THEN("it returns ::1 (with :: compression)")
            {
                REQUIRE(result == "::1");
            }
        }
    }
}

SCENARIO("ip_address_to_string formats sockaddr_in6 with port as [addr]:port", "[mdns_util][ipv6][port]")
{
    GIVEN("a sockaddr_in6 containing ::1 with port = 5353")
    {
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(5353);
        std::memset(addr.sin6_addr.s6_addr, 0, 16);
        addr.sin6_addr.s6_addr[15] = 1;

        WHEN("ip_address_to_string is called")
        {
            auto result = ip_address_to_string(addr);

            THEN("it returns [::1]:5353")
            {
                REQUIRE(result == "[::1]:5353");
            }
        }
    }
}

SCENARIO("ip_address_to_string formats sockaddr_in with port = 0 (no port suffix)", "[mdns_util][ipv4][no-port]")
{
    GIVEN("a sockaddr_in containing 10.0.0.1 with port = 0")
    {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = 0;
        // 10.0.0.1 in network byte order
        auto *b = reinterpret_cast<uint8_t *>(&addr.sin_addr);
        b[0] = 10; b[1] = 0; b[2] = 0; b[3] = 1;

        WHEN("ip_address_to_string is called")
        {
            auto result = ip_address_to_string(addr);

            THEN("it returns 10.0.0.1 without a port suffix")
            {
                REQUIRE(result == "10.0.0.1");
            }
        }
    }
}

SCENARIO("ip_address_to_string returns empty for unknown sa_family", "[mdns_util][unknown]")
{
    GIVEN("a sockaddr with sa_family = AF_UNSPEC (0)")
    {
        sockaddr addr{};
        addr.sa_family = AF_UNSPEC;

        WHEN("ip_address_to_string is called")
        {
            auto result = ip_address_to_string(&addr, sizeof(addr));

            THEN("it returns an empty string")
            {
                REQUIRE(result.empty());
            }
        }
    }
}

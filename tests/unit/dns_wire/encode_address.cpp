#include "helpers.h"

SCENARIO("encode_ipv6 encodes valid IPv6 addresses", "[response_detail][encode_ipv6]")
{
    GIVEN("the loopback address ::1")
    {
        auto result = mdnspp::detail::encode_ipv6("::1");
        THEN("it returns 16 bytes")
        {
            REQUIRE(result.has_value());
            REQUIRE(result->size() == 16);
        }
    }

    GIVEN("a link-local address fe80::1")
    {
        auto result = mdnspp::detail::encode_ipv6("fe80::1");
        THEN("it returns 16 bytes")
        {
            REQUIRE(result.has_value());
            REQUIRE(result->size() == 16);
        }
    }
}

SCENARIO("encode_ipv4 returns empty for bad octet", "[response_detail][encode_ipv4]")
{
    GIVEN("an IPv4 address with an octet > 255")
    {
        auto result = mdnspp::detail::encode_ipv4("999.0.0.1");
        THEN("it returns an error with invalid_ipv4_address")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_ipv4_address);
        }
    }
}

SCENARIO("encode_ipv4 returns empty for wrong number of octets", "[response_detail][encode_ipv4]")
{
    GIVEN("an IPv4 address with only 3 octets")
    {
        auto result = mdnspp::detail::encode_ipv4("1.2.3");
        THEN("it returns an error with invalid_ipv4_address")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_ipv4_address);
        }
    }
}

SCENARIO("encode_ipv4 encodes a valid address", "[response_detail][encode_ipv4]")
{
    GIVEN("a valid IPv4 address 192.168.1.1")
    {
        auto result = mdnspp::detail::encode_ipv4("192.168.1.1");
        THEN("it returns 4 bytes")
        {
            REQUIRE(result.has_value());
            REQUIRE(result->size() == 4);
        }
    }
}

SCENARIO("encode_ipv4 returns error for non-IP string", "[response_detail][encode_ipv4]")
{
    GIVEN("a non-IP string 'not-an-ip'")
    {
        auto result = mdnspp::detail::encode_ipv4("not-an-ip");
        THEN("it returns an error with invalid_ipv4_address")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_ipv4_address);
        }
    }
}

SCENARIO("encode_ipv4 returns error for empty string", "[response_detail][encode_ipv4]")
{
    GIVEN("an empty string")
    {
        auto result = mdnspp::detail::encode_ipv4("");
        THEN("it returns an error")
        {
            REQUIRE_FALSE(result.has_value());
        }
    }
}

SCENARIO("encode_ipv6 returns error for non-IPv6 string", "[response_detail][encode_ipv6]")
{
    GIVEN("a non-IPv6 string 'not-an-ipv6'")
    {
        auto result = mdnspp::detail::encode_ipv6("not-an-ipv6");
        THEN("it returns an error with invalid_ipv6_address")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_ipv6_address);
        }
    }
}

SCENARIO("encode_ipv6 returns error for empty string", "[response_detail][encode_ipv6]")
{
    GIVEN("an empty string")
    {
        auto result = mdnspp::detail::encode_ipv6("");
        THEN("it returns an error with invalid_ipv6_address")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_ipv6_address);
        }
    }
}

SCENARIO("mdns_error invalid address codes have correct message strings",
         "[response_detail][mdns_error]")
{
    GIVEN("the invalid_ipv4_address error code")
    {
        auto ec = mdnspp::make_error_code(mdnspp::mdns_error::invalid_ipv4_address);
        THEN("message is 'invalid IPv4 address'")
        {
            REQUIRE(ec.message() == "invalid IPv4 address");
        }
    }

    GIVEN("the invalid_ipv6_address error code")
    {
        auto ec = mdnspp::make_error_code(mdnspp::mdns_error::invalid_ipv6_address);
        THEN("message is 'invalid IPv6 address'")
        {
            REQUIRE(ec.message() == "invalid IPv6 address");
        }
    }
}

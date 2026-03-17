// Unit tests for encode_ipv4, encode_ipv6, encode_txt_records,
// encode_dns_name, and skip_dns_name edge cases.

#include "helpers.h"

using mdnspp::detail::encode_dns_name;
using mdnspp::detail::skip_dns_name;

SCENARIO("encode_ipv6 encodes valid IPv6 addresses", "[response_detail][encode_ipv6]")
{
    GIVEN("the loopback address ::1")
    {
        auto result = mdnspp::detail::encode_ipv6("::1");
        THEN("it returns 16 bytes")
        {
            REQUIRE(result.size() == 16);
        }
    }

    GIVEN("a link-local address fe80::1")
    {
        auto result = mdnspp::detail::encode_ipv6("fe80::1");
        THEN("it returns 16 bytes")
        {
            REQUIRE(result.size() == 16);
        }
    }
}

SCENARIO("encode_ipv4 returns empty for bad octet", "[response_detail][encode_ipv4]")
{
    GIVEN("an IPv4 address with an octet > 255")
    {
        auto result = mdnspp::detail::encode_ipv4("999.0.0.1");
        THEN("it returns an empty vector")
        {
            REQUIRE(result.empty());
        }
    }
}

SCENARIO("encode_ipv4 returns empty for wrong number of octets", "[response_detail][encode_ipv4]")
{
    GIVEN("an IPv4 address with only 3 octets")
    {
        auto result = mdnspp::detail::encode_ipv4("1.2.3");
        THEN("it returns an empty vector")
        {
            REQUIRE(result.empty());
        }
    }
}

SCENARIO("encode_txt_records handles entry with value, entry without value, and clamped entry", "[response_detail][encode_txt_records]")
{
    GIVEN("a set of TXT entries including one >255 chars")
    {
        std::string long_value(300, 'x');
        std::vector<mdnspp::service_txt> entries = {
            mdnspp::service_txt{"key", "val"},
            mdnspp::service_txt{"flag", std::nullopt},
            mdnspp::service_txt{"big", long_value},
        };

        auto result = mdnspp::detail::encode_txt_records(entries);

        THEN("the result is non-empty")
        {
            REQUIRE_FALSE(result.empty());
        }

        THEN("the first entry is encoded as 'key=val' with length prefix 7")
        {
            REQUIRE(static_cast<uint8_t>(result[0]) == 7); // "key=val" = 7 chars
        }

        THEN("the second entry is 'flag' with length prefix 4")
        {
            // Offset after first entry: 1 + 7 = 8
            REQUIRE(static_cast<uint8_t>(result[8]) == 4); // "flag" = 4 chars
        }

        THEN("the third entry is clamped to 255 bytes")
        {
            // Offset after second entry: 8 + 1 + 4 = 13
            REQUIRE(static_cast<uint8_t>(result[13]) == 255);
        }
    }
}

// ---------------------------------------------------------------------------
// encode_dns_name edge cases
// ---------------------------------------------------------------------------

SCENARIO("encode_dns_name with empty string returns single null byte", "[dns_read][encode_dns_name]")
{
    GIVEN("an empty DNS name string")
    {
        auto result = encode_dns_name("");

        THEN("it returns a single \\x00 root label byte")
        {
            REQUIRE(result.size() == 1);
            REQUIRE(result[0] == std::byte{0});
        }
    }
}

SCENARIO("encode_dns_name with trailing dot produces same encoding as without", "[dns_read][encode_dns_name]")
{
    GIVEN("the name 'local.' with trailing dot")
    {
        auto with_dot = encode_dns_name("local.");
        auto without_dot = encode_dns_name("local");

        THEN("both produce identical wire encodings")
        {
            REQUIRE(with_dot == without_dot);
        }
    }
}

// ---------------------------------------------------------------------------
// skip_dns_name edge cases
// ---------------------------------------------------------------------------

SCENARIO("skip_dns_name with pointer where second byte is at end of buffer", "[dns_read][skip_dns_name]")
{
    GIVEN("a 1-byte buffer containing only the pointer tag 0xC0")
    {
        auto buf = bytes({0xC0});
        size_t offset = 0;

        WHEN("skip_dns_name is called")
        {
            bool ok = skip_dns_name(std::span<const std::byte>(buf), offset);

            THEN("it returns false because pointer needs 2 bytes")
            {
                REQUIRE_FALSE(ok);
            }
        }
    }
}

SCENARIO("skip_dns_name where label extends past end of buffer", "[dns_read][skip_dns_name]")
{
    GIVEN("a buffer where a label claims 10 bytes but only 3 follow")
    {
        auto buf = bytes({0x0A, 'a', 'b', 'c'});
        size_t offset = 0;

        WHEN("skip_dns_name is called")
        {
            bool ok = skip_dns_name(std::span<const std::byte>(buf), offset);

            THEN("it returns false because label overflows buffer")
            {
                REQUIRE_FALSE(ok);
            }
        }
    }
}

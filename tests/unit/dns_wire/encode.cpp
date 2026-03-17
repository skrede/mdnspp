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

SCENARIO("encode_dns_name rejects labels exceeding 63 bytes", "[dns_read][encode_dns_name]")
{
    GIVEN("a name with a 64-byte label")
    {
        std::string long_label(64, 'a');
        auto result = encode_dns_name(long_label);
        THEN("it returns empty") { REQUIRE(result.empty()); }
    }

    GIVEN("a name with a 63-byte label")
    {
        std::string label(63, 'a');
        auto result = encode_dns_name(label);
        THEN("it encodes successfully") { REQUIRE_FALSE(result.empty()); }
    }

    GIVEN("a multi-label name where one label exceeds 63 bytes")
    {
        std::string name = "short." + std::string(64, 'b') + ".end";
        auto result = encode_dns_name(name);
        THEN("it returns empty") { REQUIRE(result.empty()); }
    }

    GIVEN("the fuzz crash input with a 192-byte label causing uint8_t truncation to 0xC0")
    {
        std::string input;
        input += "p.";
        input += std::string(45, '\xff');
        input += "c.";
        input += std::string(192, 'C');
        auto result = encode_dns_name(input);
        THEN("it returns empty because the third label exceeds 63 bytes")
        {
            REQUIRE(result.empty());
        }
    }
}

SCENARIO("read_dns_name rejects labels exceeding 63 bytes", "[dns_read][read_dns_name]")
{
    using mdnspp::detail::read_dns_name;

    GIVEN("wire data with a 64-byte label")
    {
        std::vector<std::byte> wire;
        wire.push_back(std::byte{64});
        for(int32_t i = 0; i < 64; ++i)
            wire.push_back(std::byte{'a'});
        wire.push_back(std::byte{0});

        auto result = read_dns_name(std::span<const std::byte>(wire), 0);
        THEN("it returns parse_error") { REQUIRE_FALSE(result.has_value()); }
    }

    GIVEN("wire data with a 63-byte label")
    {
        std::vector<std::byte> wire;
        wire.push_back(std::byte{63});
        for(int32_t i = 0; i < 63; ++i)
            wire.push_back(std::byte{'a'});
        wire.push_back(std::byte{0});

        auto result = read_dns_name(std::span<const std::byte>(wire), 0);
        THEN("it decodes successfully") { REQUIRE(result.has_value()); }
    }
}

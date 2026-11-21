#include "helpers.h"

using mdnspp::mdns_error;
using mdnspp::detail::read_dns_name;

namespace {

std::vector<std::byte> repeated_labels(int32_t count, uint8_t length)
{
    std::vector<std::byte> buf;
    for(int32_t i = 0; i < count; ++i)
    {
        buf.push_back(std::byte{length});
        for(int32_t j = 0; j < length; ++j)
            buf.push_back(std::byte{'a'});
    }
    buf.push_back(std::byte{0});
    return buf;
}

}

SCENARIO("read_dns_name rejects a self-referential pointer", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a 14-byte buffer where offset 12 contains a pointer back to offset 12 ({0xC0, 0x0C})")
    {
        // RFC 9267 section 2: a pointer must point strictly backward, so a pointer to itself is rejected.
        auto buf = bytes({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xC0, 0x0C});
        WHEN("read_dns_name is called at offset 12")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 12);
            THEN("it returns parse_error because ptr_target (12) >= offset (12)")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("read_dns_name rejects a forward pointer", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a buffer where the pointer at offset 5 targets offset 10 (forward)")
    {
        auto buf = bytes({
            0x04, 'h', 'o', 's', 't',
            0xC0, 0x0A, // offset 5: pointer to offset 10
            0x00, 0x00, 0x00,
            0x05, 'l', 'o', 'c', 'a', 'l', 0x00 // offset 10
        });
        WHEN("read_dns_name is called at offset 5")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 5);
            THEN("it returns parse_error because ptr_target (10) >= offset (5)")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("read_dns_name rejects a pointer chain exceeding 4 hops", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a buffer with a 5-hop backward pointer chain")
    {
        auto buf = bytes({
            0x05, 'l', 'o', 'c', 'a', 'l', 0x00, // offset 0
            0xC0, 0x00, // offset 7: pointer to 0
            0xC0, 0x07, // offset 9: pointer to 7
            0xC0, 0x09, // offset 11: pointer to 9
            0xC0, 0x0B, // offset 13: pointer to 11
            0xC0, 0x0D  // offset 15: pointer to 13, the fifth hop
        });
        WHEN("read_dns_name is called at offset 15 (5-hop chain)")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 15);
            THEN("it returns parse_error because hop count exceeds 4")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("read_dns_name accepts a pointer chain of exactly 4 hops", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a buffer with a 4-hop backward pointer chain terminating at a real name")
    {
        auto buf = bytes({
            0x05, 'l', 'o', 'c', 'a', 'l', 0x00, // offset 0
            0xC0, 0x00, // offset 7: pointer to 0
            0xC0, 0x07, // offset 9: pointer to 7
            0xC0, 0x09, // offset 11: pointer to 9
            0xC0, 0x0B  // offset 13: pointer to 11, the fourth hop
        });
        WHEN("read_dns_name is called at offset 13 (4-hop chain)")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 13);
            THEN("it succeeds and returns local.")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "local.");
            }
        }
    }
}

SCENARIO("read_dns_name rejects a name exceeding 255 bytes", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a buffer with labels totalling more than 255 bytes")
    {
        // 9 labels of 28 bytes joined by 8 dots assemble to 260 bytes
        auto buf = repeated_labels(9, 0x1C);
        WHEN("read_dns_name is called")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);
            THEN("it returns parse_error because assembled name exceeds 255 bytes")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("read_dns_name rejects a truncated buffer mid-label", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a buffer where the label length byte claims more bytes than are available")
    {
        auto buf = bytes({0x0A, 'a', 'b', 'c', 'd', 'e'});
        WHEN("read_dns_name is called")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);
            THEN("it returns parse_error because buffer is truncated mid-label")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("read_dns_name rejects a truncated buffer mid-pointer", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a buffer where a pointer starts but has only 1 byte (pointer requires 2)")
    {
        auto buf = bytes({0xC0});
        WHEN("read_dns_name is called")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);
            THEN("it returns parse_error because pointer is incomplete")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("read_dns_name rejects an offset beyond the buffer size", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a valid buffer and an offset past the end")
    {
        auto buf = bytes({0x04, 'h', 'o', 's', 't', 0x00});
        WHEN("read_dns_name is called with offset = buffer size")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), buf.size());
            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("read_dns_name rejects labels exceeding 63 bytes", "[dns_read][read_dns_name]")
{
    GIVEN("wire data with a 64-byte label")
    {
        auto wire = repeated_labels(1, 64);
        auto result = read_dns_name(std::span<const std::byte>(wire), 0);
        THEN("it returns parse_error") { REQUIRE_FALSE(result.has_value()); }
    }

    GIVEN("wire data with a 63-byte label")
    {
        auto wire = repeated_labels(1, 63);
        auto result = read_dns_name(std::span<const std::byte>(wire), 0);
        THEN("it decodes successfully") { REQUIRE(result.has_value()); }
    }
}

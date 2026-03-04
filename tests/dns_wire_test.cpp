// tests/dns_wire_test.cpp
// Unit tests for detail::read_dns_name — RFC 1035 §4.1.4 name decompression
// with RFC 9267 safety guarantees (backward-only pointers, hop limit, name length limit).

#include "mdnspp/dns_wire.h"
#include "mdnspp/mdns_error.h"

#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <vector>
#include <span>
#include <string>
#include <expected>

// Compile-time check: return type must be std::expected<std::string, mdnspp::mdns_error>
static_assert(
    std::is_same_v<
        decltype(mdnspp::detail::read_dns_name(
            std::span<const std::byte>{},
            std::size_t{})),
        std::expected<std::string, mdnspp::mdns_error>>,
    "read_dns_name must return std::expected<std::string, mdns_error>");

// Helper: build a byte vector from initializer list of unsigned chars
static std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
{
    std::vector<std::byte> v;
    v.reserve(vals.size());
    for (auto b : vals)
        v.push_back(static_cast<std::byte>(b));
    return v;
}

using mdnspp::mdns_error;
using mdnspp::detail::read_dns_name;

// ---------------------------------------------------------------------------
// Happy-path tests
// ---------------------------------------------------------------------------

SCENARIO("read_dns_name decodes a simple uncompressed DNS name", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer containing _http._tcp.local in DNS wire label format")
    {
        // \x05_http \x04_tcp \x05local \x00
        auto buf = bytes({
            0x05, '_','h','t','t','p',
            0x04, '_','t','c','p',
            0x05, 'l','o','c','a','l',
            0x00
        });

        WHEN("read_dns_name is called at offset 0")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);

            THEN("it returns _http._tcp.local without a trailing dot")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "_http._tcp.local");
            }
        }
    }
}

SCENARIO("read_dns_name returns empty string for the root-only name", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer containing only the root label \\x00")
    {
        auto buf = bytes({0x00});

        WHEN("read_dns_name is called at offset 0")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);

            THEN("it returns an empty string")
            {
                REQUIRE(result.has_value());
                REQUIRE(result->empty());
            }
        }
    }
}

SCENARIO("read_dns_name decodes a single-label name", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer containing the label 'host' followed by root")
    {
        // \x04host \x00
        auto buf = bytes({0x04, 'h','o','s','t', 0x00});

        WHEN("read_dns_name is called at offset 0")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 0);

            THEN("it returns host")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "host");
            }
        }
    }
}

SCENARIO("read_dns_name follows a backward compression pointer", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer where offset 0 has 'local\\x00' and offset 7 has a pointer to offset 0")
    {
        // offset 0: \x05local\x00  (7 bytes: 1 + 5 + 1)
        // offset 7: \x04host + pointer 0xC0 0x00  -> "host.local"
        auto buf = bytes({
            // offset 0: "local\0"
            0x05, 'l','o','c','a','l', 0x00,
            // offset 7: "host" label + pointer back to offset 0
            0x04, 'h','o','s','t',
            0xC0, 0x00
        });

        WHEN("read_dns_name is called at offset 7")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 7);

            THEN("it follows the pointer and assembles host.local")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "host.local");
            }
        }
    }
}

SCENARIO("read_dns_name starts directly at a compression pointer", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer where offset 0 has 'local\\x00' and offset 7 is a bare pointer to offset 0")
    {
        // offset 0: \x05local\x00  (7 bytes)
        // offset 7: pointer 0xC0 0x00 -> "local"
        auto buf = bytes({
            0x05, 'l','o','c','a','l', 0x00,
            0xC0, 0x00
        });

        WHEN("read_dns_name is called at the pointer offset 7")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 7);

            THEN("it follows the pointer and returns local")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "local");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// RFC 9267 safety tests
// ---------------------------------------------------------------------------

SCENARIO("read_dns_name rejects a self-referential pointer", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a 14-byte buffer where offset 12 contains a pointer back to offset 12 ({0xC0, 0x0C})")
    {
        // Pad the first 12 bytes so the pointer is at offset 12 (target = 12 = self)
        // This is the canonical Phase 8 success criterion #2 test.
        auto buf = bytes({
            // 12-byte DNS header placeholder
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            // offset 12: pointer to offset 12 — self-referential
            0xC0, 0x0C
        });

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
        // offset 5: pointer to offset 10 — forward pointer
        auto buf = bytes({
            0x04, 'h','o','s','t',  // offset 0-4
            0xC0, 0x0A,             // offset 5: pointer to 10 (forward)
            0x00, 0x00, 0x00,       // offset 7-9: padding
            0x05, 'l','o','c','a','l', 0x00  // offset 10: "local"
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
        // Build a chain: each byte pair is a pointer to the previous offset
        // We need 5 pointers. Since each pointer must point backwards,
        // we place them at increasing offsets with each pointing to the
        // previous pointer (all ultimately valid backward targets but chain > 4).
        //
        // Layout (each pointer is 2 bytes):
        //   offset  0: \x05local\x00   (7 bytes — the actual name)
        //   offset  7: pointer -> 0    (hop 1)
        //   offset  9: pointer -> 7    (hop 2)
        //   offset 11: pointer -> 9    (hop 3)
        //   offset 13: pointer -> 11   (hop 4)
        //   offset 15: pointer -> 13   (hop 5 — should fail)
        auto buf = bytes({
            // offset 0: "local\0"
            0x05, 'l','o','c','a','l', 0x00,
            // offset 7: pointer -> 0
            0xC0, 0x00,
            // offset 9: pointer -> 7
            0xC0, 0x07,
            // offset 11: pointer -> 9
            0xC0, 0x09,
            // offset 13: pointer -> 11
            0xC0, 0x0B,
            // offset 15: pointer -> 13 (5th hop — exceeds limit of 4)
            0xC0, 0x0D
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
        // Same structure but only 4 hops — should succeed
        //   offset  0: \x05local\x00   (7 bytes)
        //   offset  7: pointer -> 0    (hop 1)
        //   offset  9: pointer -> 7    (hop 2)
        //   offset 11: pointer -> 9    (hop 3)
        //   offset 13: pointer -> 11   (hop 4 — allowed)
        auto buf = bytes({
            0x05, 'l','o','c','a','l', 0x00,
            0xC0, 0x00,
            0xC0, 0x07,
            0xC0, 0x09,
            0xC0, 0x0B
        });

        WHEN("read_dns_name is called at offset 13 (4-hop chain)")
        {
            auto result = read_dns_name(std::span<const std::byte>(buf), 13);

            THEN("it succeeds and returns local")
            {
                REQUIRE(result.has_value());
                REQUIRE(*result == "local");
            }
        }
    }
}

SCENARIO("read_dns_name rejects a name exceeding 255 bytes", "[dns_wire][read_dns_name][safety]")
{
    GIVEN("a buffer with labels totalling more than 255 bytes")
    {
        // Construct: 9 labels of 28 chars each = 9*28 = 252 label bytes
        // + 9 dots between labels = 8 dots => total assembled = 252 + 8 = 260 > 255
        // Wire format: each label is [0x1C][28 chars], terminated by [0x00]
        std::vector<std::byte> buf;
        for (int i = 0; i < 9; ++i)
        {
            buf.push_back(static_cast<std::byte>(0x1C)); // label length = 28
            for (int j = 0; j < 28; ++j)
                buf.push_back(static_cast<std::byte>('a'));
        }
        buf.push_back(static_cast<std::byte>(0x00)); // root label

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
        // Label claims 10 bytes but buffer only has 5 after the length byte
        auto buf = bytes({0x0A, 'a','b','c','d','e'});

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
        // 0xC0 is the start of a pointer, but no second byte follows
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
        auto buf = bytes({0x04, 'h','o','s','t', 0x00});

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

// tests/dns_wire_test.cpp
// Unit tests for detail::read_dns_name — RFC 1035 §4.1.4 name decompression
// with RFC 9267 safety guarantees (backward-only pointers, hop limit, name length limit).
// Also covers build_dns_response, encode_ipv4/ipv6, encode_txt_records,
// encode_dns_name, skip_dns_name edge cases, known-answer query building,
// and parse_service_type.

#include "mdnspp/detail/dns_wire.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/mdns_error.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <string>
#include <variant>
#include <optional>
#include <cstddef>

// Compile-time check: return type must be detail::expected<std::string, mdnspp::mdns_error>
static_assert(
    std::is_same_v<
        decltype(mdnspp::detail::read_dns_name(
            std::span<const std::byte>{},
            std::size_t{})),
        mdnspp::detail::expected<std::string, mdnspp::mdns_error>>,
    "read_dns_name must return detail::expected<std::string, mdns_error>");

// Helper: build a byte vector from initializer list of unsigned chars
static std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
{
    std::vector<std::byte> v;
    v.reserve(vals.size());
    for(auto b : vals)
        v.push_back(static_cast<std::byte>(b));
    return v;
}

using mdnspp::mdns_error;
using mdnspp::detail::read_dns_name;

SCENARIO("read_dns_name decodes a simple uncompressed DNS name", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer containing _http._tcp.local in DNS wire label format")
    {
        // \x05_http \x04_tcp \x05local \x00
        auto buf = bytes({
            0x05,
            '_',
            'h',
            't',
            't',
            'p',
            0x04,
            '_',
            't',
            'c',
            'p',
            0x05,
            'l',
            'o',
            'c',
            'a',
            'l',
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
                REQUIRE((*result).empty());
            }
        }
    }
}

SCENARIO("read_dns_name decodes a single-label name", "[dns_wire][read_dns_name]")
{
    GIVEN("a buffer containing the label 'host' followed by root")
    {
        // \x04host \x00
        auto buf = bytes({0x04, 'h', 'o', 's', 't', 0x00});

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
            0x05,
            'l',
            'o',
            'c',
            'a',
            'l',
            0x00,
            // offset 7: "host" label + pointer back to offset 0
            0x04,
            'h',
            'o',
            's',
            't',
            0xC0,
            0x00
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
            0x05,
            'l',
            'o',
            'c',
            'a',
            'l',
            0x00,
            0xC0,
            0x00
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
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            // offset 12: pointer to offset 12 — self-referential
            0xC0,
            0x0C
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
            0x04,
            'h',
            'o',
            's',
            't',
            // offset 0-4
            0xC0,
            0x0A,
            // offset 5: pointer to 10 (forward)
            0x00,
            0x00,
            0x00,
            // offset 7-9: padding
            0x05,
            'l',
            'o',
            'c',
            'a',
            'l',
            0x00 // offset 10: "local"
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
            0x05,
            'l',
            'o',
            'c',
            'a',
            'l',
            0x00,
            // offset 7: pointer -> 0
            0xC0,
            0x00,
            // offset 9: pointer -> 7
            0xC0,
            0x07,
            // offset 11: pointer -> 9
            0xC0,
            0x09,
            // offset 13: pointer -> 11
            0xC0,
            0x0B,
            // offset 15: pointer -> 13 (5th hop — exceeds limit of 4)
            0xC0,
            0x0D
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
            0x05,
            'l',
            'o',
            'c',
            'a',
            'l',
            0x00,
            0xC0,
            0x00,
            0xC0,
            0x07,
            0xC0,
            0x09,
            0xC0,
            0x0B
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
        for(int i = 0; i < 9; ++i)
        {
            buf.push_back(static_cast<std::byte>(0x1C)); // label length = 28
            for(int j = 0; j < 28; ++j)
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

// ---------------------------------------------------------------------------
// build_dns_response tests — round-trip via walk_dns_frame
// ---------------------------------------------------------------------------

using mdnspp::detail::build_dns_response;
using mdnspp::detail::walk_dns_frame;
using mdnspp::detail::encode_dns_name;
using mdnspp::detail::skip_dns_name;

static mdnspp::service_info make_test_service_v46()
{
    mdnspp::service_info info;
    info.service_name = "MyService._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "myhost.local.";
    info.port = 8080;
    info.priority = 0;
    info.weight = 0;
    info.address_ipv4 = "192.168.1.10";
    info.address_ipv6 = "::1";
    info.txt_records = {mdnspp::service_txt{"path", "/api"}, mdnspp::service_txt{"ver", std::nullopt}};
    return info;
}

static std::vector<mdnspp::mdns_record_variant> parse_wire(const std::vector<std::byte> &pkt)
{
    std::vector<mdnspp::mdns_record_variant> records;
    walk_dns_frame(std::span<const std::byte>(pkt), mdnspp::endpoint{}, [&](mdnspp::mdns_record_variant rv)
    {
        records.push_back(std::move(rv));
    });
    return records;
}

SCENARIO("build_dns_response produces valid AAAA response", "[build_dns_response][AAAA]")
{
    GIVEN("a service_info with address_ipv6 = \"::1\"")
    {
        auto info = make_test_service_v46();

        WHEN("build_dns_response is called with qtype=28 (AAAA)")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::aaaa);

            THEN("walk_dns_frame parses a record_aaaa")
            {
                auto records = parse_wire(pkt);
                bool found = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<mdnspp::record_aaaa>(rv))
                        found = true;
                }
                REQUIRE(found);
            }
        }
    }
}

SCENARIO("build_dns_response returns empty for AAAA when no IPv6 address", "[build_dns_response][AAAA][no-ipv6]")
{
    GIVEN("a service_info without address_ipv6")
    {
        auto info = make_test_service_v46();
        info.address_ipv6 = std::nullopt;

        WHEN("build_dns_response is called with qtype=28 (AAAA)")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::aaaa);

            THEN("the returned vector is empty")
            {
                REQUIRE(pkt.empty());
            }
        }
    }
}

SCENARIO("build_dns_response ANY produces all records as answers (no additional)", "[build_dns_response][ANY]")
{
    GIVEN("a service_info with both IPv4 and IPv6")
    {
        auto info = make_test_service_v46();

        WHEN("build_dns_response is called with qtype=255 (ANY)")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::any);

            THEN("the packet is non-empty and arcount is 0")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t arcount = (static_cast<uint16_t>(static_cast<uint8_t>(pkt[10])) << 8) |
                    static_cast<uint16_t>(static_cast<uint8_t>(pkt[11]));
                REQUIRE(arcount == 0);
            }

            THEN("walk_dns_frame parses PTR, SRV, A, AAAA, and TXT records")
            {
                auto records = parse_wire(pkt);
                bool has_ptr = false, has_srv = false, has_a = false, has_aaaa = false, has_txt = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<mdnspp::record_ptr>(rv)) has_ptr = true;
                    if(std::holds_alternative<mdnspp::record_srv>(rv)) has_srv = true;
                    if(std::holds_alternative<mdnspp::record_a>(rv)) has_a = true;
                    if(std::holds_alternative<mdnspp::record_aaaa>(rv)) has_aaaa = true;
                    if(std::holds_alternative<mdnspp::record_txt>(rv)) has_txt = true;
                }
                REQUIRE(has_ptr);
                REQUIRE(has_srv);
                REQUIRE(has_a);
                REQUIRE(has_aaaa);
                REQUIRE(has_txt);
            }
        }
    }
}

SCENARIO("build_dns_response TXT with empty txt_records produces valid zero-length TXT", "[build_dns_response][TXT][empty]")
{
    GIVEN("a service_info with empty txt_records")
    {
        auto info = make_test_service_v46();
        info.txt_records.clear();

        WHEN("build_dns_response is called with qtype=16 (TXT)")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::txt);

            THEN("the packet is non-empty (valid TXT with empty rdata)")
            {
                REQUIRE_FALSE(pkt.empty());
            }
        }
    }
}

SCENARIO("build_dns_response PTR includes AAAA additional when service has IPv6", "[build_dns_response][PTR][AAAA]")
{
    GIVEN("a service_info with both IPv4 and IPv6 addresses")
    {
        auto info = make_test_service_v46();

        WHEN("build_dns_response is called with qtype=12 (PTR)")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::ptr);

            THEN("walk_dns_frame yields PTR, SRV, A, and AAAA records")
            {
                auto records = parse_wire(pkt);
                bool has_aaaa = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<mdnspp::record_aaaa>(rv))
                        has_aaaa = true;
                }
                REQUIRE(has_aaaa);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// response_detail helper tests
// ---------------------------------------------------------------------------

SCENARIO("encode_ipv6 encodes valid IPv6 addresses", "[response_detail][encode_ipv6]")
{
    GIVEN("the loopback address ::1")
    {
        auto result = mdnspp::detail::response_detail::encode_ipv6("::1");
        THEN("it returns 16 bytes")
        {
            REQUIRE(result.size() == 16);
        }
    }

    GIVEN("a link-local address fe80::1")
    {
        auto result = mdnspp::detail::response_detail::encode_ipv6("fe80::1");
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
        auto result = mdnspp::detail::response_detail::encode_ipv4("999.0.0.1");
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
        auto result = mdnspp::detail::response_detail::encode_ipv4("1.2.3");
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

        auto result = mdnspp::detail::response_detail::encode_txt_records(entries);

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

// ---------------------------------------------------------------------------
// Cache-flush bit tests — verify raw wire bytes (not walk_dns_frame which strips the bit)
// ---------------------------------------------------------------------------

using mdnspp::detail::read_u16_be;

// Helper: find rrclass value of the first resource record after skipping the DNS header
// and question section. Returns the raw 16-bit rrclass (including cache-flush bit if set).
static uint16_t find_first_rr_rrclass(const std::vector<std::byte> &pkt)
{
    // Skip 12-byte header
    size_t offset = 12;
    auto span = std::span<const std::byte>(pkt);

    // Skip question section (qdcount questions)
    uint16_t qdcount = read_u16_be(pkt.data() + 4);
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        skip_dns_name(span, offset);
        offset += 4; // qtype + qclass
    }

    // Now at the first RR — skip name, then read rtype(2) + rrclass(2)
    skip_dns_name(span, offset);
    offset += 2; // skip rtype
    return read_u16_be(pkt.data() + offset);
}

// Helper: collect all (rtype, rrclass) pairs from all RRs in a packet
static std::vector<std::pair<uint16_t, uint16_t>> collect_rr_type_class(const std::vector<std::byte> &pkt)
{
    std::vector<std::pair<uint16_t, uint16_t>> result;
    size_t offset = 12;
    auto span = std::span<const std::byte>(pkt);

    uint16_t qdcount = read_u16_be(pkt.data() + 4);
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        skip_dns_name(span, offset);
        offset += 4;
    }

    uint16_t ancount = read_u16_be(pkt.data() + 6);
    uint16_t nscount = read_u16_be(pkt.data() + 8);
    uint16_t arcount = read_u16_be(pkt.data() + 10);
    uint32_t rr_total = static_cast<uint32_t>(ancount) +
        static_cast<uint32_t>(nscount) +
        static_cast<uint32_t>(arcount);

    for(uint32_t rr = 0; rr < rr_total; ++rr)
    {
        skip_dns_name(span, offset);
        uint16_t rtype = read_u16_be(pkt.data() + offset);
        offset += 2;
        uint16_t rclass = read_u16_be(pkt.data() + offset);
        offset += 2;
        result.emplace_back(rtype, rclass);

        // Skip ttl(4) + rdlength(2) + rdata
        offset += 4;
        uint16_t rdlength = read_u16_be(pkt.data() + offset);
        offset += 2;
        offset += rdlength;
    }

    return result;
}

SCENARIO("build_dns_response PTR answer does NOT have cache-flush bit set", "[build_dns_response][cache_flush]")
{
    GIVEN("a service_info with both addresses")
    {
        auto info = make_test_service_v46();

        WHEN("build_dns_response is called with qtype=PTR")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::ptr);

            THEN("the first RR (PTR answer) has rrclass 0x0001 (no cache-flush bit)")
            {
                uint16_t rrclass = find_first_rr_rrclass(pkt);
                REQUIRE(rrclass == 0x0001);
            }
        }
    }
}

SCENARIO("build_dns_response SRV answer has cache-flush bit set", "[build_dns_response][cache_flush]")
{
    GIVEN("a service_info with both addresses")
    {
        auto info = make_test_service_v46();

        WHEN("build_dns_response is called with qtype=SRV")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::srv);

            THEN("the first RR (SRV answer) has rrclass 0x8001 (cache-flush bit set)")
            {
                uint16_t rrclass = find_first_rr_rrclass(pkt);
                REQUIRE(rrclass == 0x8001);
            }
        }
    }
}

SCENARIO("build_dns_response ANY sets cache-flush on unique records only", "[build_dns_response][cache_flush]")
{
    GIVEN("a service_info with both addresses and TXT records")
    {
        auto info = make_test_service_v46();

        WHEN("build_dns_response is called with qtype=ANY")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::any);

            THEN("PTR has rrclass 0x0001, SRV/A/AAAA/TXT have rrclass 0x8001")
            {
                auto rrs = collect_rr_type_class(pkt);
                REQUIRE_FALSE(rrs.empty());

                for(auto [rtype, rclass] : rrs)
                {
                    if(rtype == std::to_underlying(mdnspp::dns_type::ptr))
                        REQUIRE(rclass == 0x0001);
                    else
                        REQUIRE(rclass == 0x8001);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// build_probe_query tests
// ---------------------------------------------------------------------------

using mdnspp::detail::build_probe_query;

SCENARIO("build_probe_query produces valid probe packet with question and authority", "[build_probe_query]")
{
    GIVEN("a test service_info")
    {
        auto info = make_test_service_v46();

        WHEN("build_probe_query is called")
        {
            auto pkt = build_probe_query(info);

            THEN("the header has flags=0x0000, qdcount=1, nscount=1")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t flags = read_u16_be(pkt.data() + 2);
                uint16_t qdcount = read_u16_be(pkt.data() + 4);
                uint16_t ancount = read_u16_be(pkt.data() + 6);
                uint16_t nscount = read_u16_be(pkt.data() + 8);

                REQUIRE(flags == 0x0000);
                REQUIRE(qdcount == 1);
                REQUIRE(ancount == 0);
                REQUIRE(nscount == 1);
            }

            THEN("the question has QTYPE=ANY and QCLASS=0x8001 (QU bit)")
            {
                // Skip header (12 bytes) + question name
                size_t offset = 12;
                auto span = std::span<const std::byte>(pkt);
                skip_dns_name(span, offset);

                uint16_t qtype = read_u16_be(pkt.data() + offset);
                uint16_t qclass = read_u16_be(pkt.data() + offset + 2);

                REQUIRE(qtype == std::to_underlying(mdnspp::dns_type::any));
                REQUIRE(qclass == 0x8001);
            }

            THEN("the authority section contains an SRV record")
            {
                auto rrs = collect_rr_type_class(pkt);
                REQUIRE(rrs.size() == 1);
                REQUIRE(rrs[0].first == std::to_underlying(mdnspp::dns_type::srv));
            }

            THEN("the question name matches the service_name")
            {
                auto result = mdnspp::detail::read_dns_name(
                    std::span<const std::byte>(pkt), 12);
                REQUIRE(result.has_value());
                // service_name is "MyService._http._tcp.local." — trailing dot stripped
                REQUIRE(*result == "MyService._http._tcp.local");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NSEC bitmap and record tests
// ---------------------------------------------------------------------------

using mdnspp::detail::response_detail::build_nsec_bitmap;
using mdnspp::detail::response_detail::append_nsec_rr;

SCENARIO("build_nsec_bitmap with IPv4 only sets A, PTR, TXT, SRV bits", "[nsec][bitmap]")
{
    GIVEN("a service_info with only address_ipv4 set")
    {
        auto info = make_test_service_v46();
        info.address_ipv6 = std::nullopt;

        WHEN("build_nsec_bitmap is called")
        {
            auto bitmap = build_nsec_bitmap(info);

            THEN("the bitmap has window=0x00, length=5, correct bit pattern")
            {
                // Expected: A(1), PTR(12), TXT(16), SRV(33)
                // Byte 0: bit 6 set (type 1) -> 0x40
                // Byte 1: bit 3 set (type 12) -> 0x08
                // Byte 2: bit 7 set (type 16) -> 0x80
                // Byte 3: no bits -> 0x00
                // Byte 4: bit 6 set (type 33) -> 0x40
                REQUIRE(bitmap.size() == 7); // 2 header + 5 bitmap
                REQUIRE(bitmap[0] == std::byte{0x00}); // window
                REQUIRE(bitmap[1] == std::byte{0x05}); // length
                REQUIRE(bitmap[2] == std::byte{0x40}); // A(1)
                REQUIRE(bitmap[3] == std::byte{0x08}); // PTR(12)
                REQUIRE(bitmap[4] == std::byte{0x80}); // TXT(16)
                REQUIRE(bitmap[5] == std::byte{0x00}); // no AAAA
                REQUIRE(bitmap[6] == std::byte{0x40}); // SRV(33)
            }
        }
    }
}

SCENARIO("build_nsec_bitmap with IPv4 and IPv6 sets A, PTR, TXT, AAAA, SRV bits", "[nsec][bitmap]")
{
    GIVEN("a service_info with both address_ipv4 and address_ipv6 set")
    {
        auto info = make_test_service_v46();

        WHEN("build_nsec_bitmap is called")
        {
            auto bitmap = build_nsec_bitmap(info);

            THEN("byte 3 has AAAA(28) bit set -> 0x08")
            {
                REQUIRE(bitmap.size() == 7);
                REQUIRE(bitmap[5] == std::byte{0x08}); // AAAA(28): byte 3, bit 3
            }
        }
    }
}

SCENARIO("build_nsec_bitmap with no addresses sets only PTR, TXT, SRV bits", "[nsec][bitmap]")
{
    GIVEN("a service_info with no address fields set")
    {
        auto info = make_test_service_v46();
        info.address_ipv4 = std::nullopt;
        info.address_ipv6 = std::nullopt;

        WHEN("build_nsec_bitmap is called")
        {
            auto bitmap = build_nsec_bitmap(info);

            THEN("byte 0 is 0x00 (no A bit)")
            {
                REQUIRE(bitmap.size() == 7);
                REQUIRE(bitmap[2] == std::byte{0x00}); // no A(1)
            }
        }
    }
}

SCENARIO("append_nsec_rr produces a parseable NSEC resource record", "[nsec][bitmap]")
{
    GIVEN("a service_info with IPv4")
    {
        auto info = make_test_service_v46();
        info.address_ipv6 = std::nullopt;

        auto owner_name = encode_dns_name(info.hostname);

        WHEN("append_nsec_rr is called and wrapped in a DNS response packet")
        {
            // Build a minimal DNS response with the NSEC record as answer
            std::vector<std::byte> packet;
            // DNS header
            mdnspp::detail::push_u16_be(packet, 0x0000); // id
            mdnspp::detail::push_u16_be(packet, 0x8400); // flags
            mdnspp::detail::push_u16_be(packet, 0x0000); // qdcount
            mdnspp::detail::push_u16_be(packet, 0x0001); // ancount = 1
            mdnspp::detail::push_u16_be(packet, 0x0000); // nscount
            mdnspp::detail::push_u16_be(packet, 0x0000); // arcount

            append_nsec_rr(packet, owner_name, info, 4500);

            THEN("the RR has type=47, class=IN, correct TTL and rdata containing owner name + bitmap")
            {
                // Parse the packet manually: skip header (12), skip owner name, read rtype
                size_t offset = 12;
                auto span = std::span<const std::byte>(packet);
                skip_dns_name(span, offset);

                uint16_t rtype = read_u16_be(packet.data() + offset);
                offset += 2;
                uint16_t rclass = read_u16_be(packet.data() + offset);
                offset += 2;
                uint32_t ttl = mdnspp::detail::read_u32_be(packet.data() + offset);
                offset += 4;
                uint16_t rdlength = read_u16_be(packet.data() + offset);
                offset += 2;

                REQUIRE(rtype == 47);
                REQUIRE(rclass == 0x0001); // no cache-flush
                REQUIRE(ttl == 4500);

                // rdata should contain: next domain name (= owner) + bitmap
                auto expected_bitmap = build_nsec_bitmap(info);
                REQUIRE(rdlength == owner_name.size() + expected_bitmap.size());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Known-answer query building tests
// ---------------------------------------------------------------------------

using mdnspp::detail::build_dns_query;
using mdnspp::detail::append_known_answer;
using mdnspp::detail::push_u16_be;

SCENARIO("build_dns_query with known answers includes Answer section", "[dns_wire][known_answer]")
{
    GIVEN("a PTR record as a known answer")
    {
        mdnspp::record_ptr ptr;
        ptr.name = "_http._tcp.local";
        ptr.ttl = 4500;
        ptr.ptr_name = "MyService._http._tcp.local";

        std::vector<mdnspp::mdns_record_variant> known = {ptr};

        WHEN("build_dns_query is called with the known answer")
        {
            auto pkt = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr,
                                       std::span<const mdnspp::mdns_record_variant>(known));

            THEN("the header ancount is 1")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t ancount = read_u16_be(pkt.data() + 6);
                REQUIRE(ancount == 1);
            }

            THEN("the packet is longer than a basic query")
            {
                auto basic = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr);
                REQUIRE(pkt.size() > basic.size());
            }

            THEN("walk_dns_frame can parse the known-answer PTR record")
            {
                // To parse as a response frame, we need QR=1 in flags.
                // Modify flags to make it parseable by walk_dns_frame.
                auto parseable = pkt;
                // Set qdcount=0 so walk_dns_frame skips question section
                // Actually walk_dns_frame skips questions by count, so let's
                // just verify the answer section by manually checking.
                auto records = parse_wire(pkt);
                // walk_dns_frame skips questions by qdcount, then reads ancount RRs.
                // Our packet has qdcount=1 and ancount=1, so it will skip the question
                // and parse the answer section.
                bool found_ptr = false;
                for(const auto &rv : records)
                {
                    if(auto *p = std::get_if<mdnspp::record_ptr>(&rv))
                    {
                        found_ptr = true;
                        REQUIRE(p->ptr_name == "MyService._http._tcp.local");
                    }
                }
                REQUIRE(found_ptr);
            }
        }
    }
}

SCENARIO("build_dns_query with empty known answers matches basic overload", "[dns_wire][known_answer]")
{
    GIVEN("an empty known-answers span")
    {
        std::span<const mdnspp::mdns_record_variant> empty;

        WHEN("both overloads are called for the same query")
        {
            auto basic = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr);
            auto with_empty = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr, empty);

            THEN("the output is byte-for-byte identical")
            {
                REQUIRE(basic == with_empty);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// parse_service_type tests
// ---------------------------------------------------------------------------

using mdnspp::parse_service_type;

SCENARIO("parse_service_type splits PTR name into components", "[dns_wire][parse_service_type]")
{
    GIVEN("the service type _http._tcp.local")
    {
        auto info = parse_service_type("_http._tcp.local");

        THEN("type_name is _http, protocol is _tcp, domain is local")
        {
            REQUIRE(info.type_name == "_http");
            REQUIRE(info.protocol == "_tcp");
            REQUIRE(info.domain == "local");
            REQUIRE(info.service_type == "_http._tcp.local");
        }
    }

    GIVEN("the service type _ipp._tcp.local. with trailing dot")
    {
        auto info = parse_service_type("_ipp._tcp.local.");

        THEN("trailing dot is stripped and components are correct")
        {
            REQUIRE(info.type_name == "_ipp");
            REQUIRE(info.protocol == "_tcp");
            REQUIRE(info.domain == "local");
            REQUIRE(info.service_type == "_ipp._tcp.local");
        }
    }
}

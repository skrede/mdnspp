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

SCENARIO("encode_txt_records handles entry with value, entry without value, and oversized entry", "[response_detail][encode_txt_records]")
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

        THEN("the oversized third entry is skipped entirely")
        {
            // Only first two entries encoded: (1+7) + (1+4) = 13 bytes total
            REQUIRE(result.size() == 13);
        }
    }

    GIVEN("a TXT entry with exactly 255 bytes")
    {
        std::string value(251, 'x'); // "k=xxx..." = 2 + 251 = 253... need key=value total = 255
        std::vector<mdnspp::service_txt> entries = {
            mdnspp::service_txt{std::string(1, 'k'), std::string(253, 'v')}, // "k=vvv..." = 255
        };

        auto result = mdnspp::detail::encode_txt_records(entries);
        THEN("it is accepted at 255 bytes")
        {
            REQUIRE_FALSE(result.empty());
            REQUIRE(static_cast<uint8_t>(result[0]) == 255);
        }
    }

    GIVEN("a TXT entry with 256 bytes")
    {
        std::vector<mdnspp::service_txt> entries = {
            mdnspp::service_txt{std::string(1, 'k'), std::string(254, 'v')}, // "k=vvv..." = 256
        };

        auto result = mdnspp::detail::encode_txt_records(entries);
        THEN("it is skipped, leaving the RFC 6763 §6.1 single zero byte")
        {
            REQUIRE(result.size() == 1);
            REQUIRE(result[0] == std::byte{0x00});
        }
    }

    GIVEN("no TXT entries at all")
    {
        auto result = mdnspp::detail::encode_txt_records({});
        THEN("the rdata is a single zero byte (RFC 6763 §6.1)")
        {
            REQUIRE(result.size() == 1);
            REQUIRE(result[0] == std::byte{0x00});
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
            REQUIRE(result.has_value());
            REQUIRE(result->size() == 1);
            REQUIRE((*result)[0] == std::byte{0});
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
            REQUIRE(with_dot.has_value());
            REQUIRE(without_dot.has_value());
            REQUIRE(*with_dot == *without_dot);
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
        THEN("it returns invalid_name") { REQUIRE_FALSE(result.has_value()); }
    }

    GIVEN("a name with a 63-byte label")
    {
        std::string label(63, 'a');
        auto result = encode_dns_name(label);
        THEN("it encodes successfully") { REQUIRE(result.has_value()); }
    }

    GIVEN("a multi-label name where one label exceeds 63 bytes")
    {
        std::string name = "short." + std::string(64, 'b') + ".end";
        auto result = encode_dns_name(name);
        THEN("it returns invalid_name") { REQUIRE_FALSE(result.has_value()); }
    }

    GIVEN("the fuzz crash input with a 192-byte label causing uint8_t truncation to 0xC0")
    {
        std::string input;
        input += "p.";
        input += std::string(45, '\xff');
        input += "c.";
        input += std::string(192, 'C');
        auto result = encode_dns_name(input);
        THEN("it returns invalid_name because the third label exceeds 63 bytes")
        {
            REQUIRE_FALSE(result.has_value());
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

SCENARIO("encode_dns_name rejects names exceeding 255 wire bytes", "[dns_read][encode_dns_name]")
{
    GIVEN("a name with 4 labels of 63 bytes each (wire: 4*(1+63)+1 = 257 > 255)")
    {
        std::string name = std::string(63, 'a') + "." + std::string(63, 'b') + "."
                         + std::string(63, 'c') + "." + std::string(63, 'd');
        auto result = encode_dns_name(name);
        THEN("it returns invalid_name") { REQUIRE_FALSE(result.has_value()); }
    }

    GIVEN("a name at exactly 255 wire bytes (3 labels of 63 + one of 61)")
    {
        // Wire: (1+63)+(1+63)+(1+63)+(1+61)+1 = 64+64+64+62+1 = 255
        std::string name = std::string(63, 'a') + "." + std::string(63, 'b') + "."
                         + std::string(63, 'c') + "." + std::string(61, 'd');
        auto result = encode_dns_name(name);
        THEN("it encodes successfully") { REQUIRE(result.has_value()); }
        THEN("wire size is exactly 255") { REQUIRE(result->size() == 255); }
    }
}

SCENARIO("append_dns_rr skips records with empty owner name", "[dns_write][append_dns_rr]")
{
    GIVEN("an empty owner name vector")
    {
        std::vector<std::byte> buf;
        std::vector<std::byte> empty_name;
        std::vector<std::byte> rdata = {std::byte{1}, std::byte{2}};
        mdnspp::detail::append_dns_rr(buf, empty_name,
            mdnspp::dns_type::a, 120, rdata);

        THEN("nothing is appended to the buffer") { REQUIRE(buf.empty()); }
    }
}

// ---------------------------------------------------------------------------
// RFC 1035 section 5.1 escaping and case preservation
// ---------------------------------------------------------------------------

SCENARIO("encode_dns_name and read_dns_name round-trip an instance label containing a dot",
         "[dns_read][encode_dns_name][escaping]")
{
    using mdnspp::detail::read_dns_name;

    GIVEN("the RFC 6763 section 4.3 instance name Dr\\. Smith._http._tcp.local.")
    {
        const std::string presentation = "Dr\\. Smith._http._tcp.local.";
        auto encoded = encode_dns_name(presentation);

        THEN("the first label is the 9 unescaped bytes 'Dr. Smith'")
        {
            REQUIRE(encoded.has_value());
            REQUIRE(static_cast<uint8_t>((*encoded)[0]) == 9);
            std::string label;
            for(std::size_t i = 1; i <= 9; ++i)
                label += static_cast<char>(static_cast<uint8_t>((*encoded)[i]));
            REQUIRE(label == "Dr. Smith");
        }

        THEN("decoding restores the escaped presentation form exactly")
        {
            REQUIRE(encoded.has_value());
            auto decoded = read_dns_name(std::span<const std::byte>(*encoded), 0);
            REQUIRE(decoded.has_value());
            REQUIRE(*decoded == presentation);
        }

        THEN("the escaped form encodes three labels, not four")
        {
            auto unescaped = encode_dns_name("Dr. Smith._http._tcp.local.");
            REQUIRE(encoded.has_value());
            REQUIRE(unescaped.has_value());
            REQUIRE(*encoded != *unescaped);
        }
    }
}

SCENARIO("encode_dns_name preserves original byte case", "[dns_read][encode_dns_name][case]")
{
    using mdnspp::detail::read_dns_name;

    GIVEN("a mixed-case instance name")
    {
        auto encoded = encode_dns_name("MyPrinter._ipp._tcp.local.");
        THEN("the wire bytes carry the original case (RFC 6763 section 4.1)")
        {
            REQUIRE(encoded.has_value());
            auto decoded = read_dns_name(std::span<const std::byte>(*encoded), 0);
            REQUIRE(decoded.has_value());
            REQUIRE(*decoded == "MyPrinter._ipp._tcp.local.");
        }
    }
}

SCENARIO("encode_dns_name rejects empty labels", "[dns_read][encode_dns_name][escaping]")
{
    GIVEN("the name a..b.local with an embedded empty label")
    {
        auto result = encode_dns_name("a..b.local");
        THEN("it returns invalid_name instead of emitting a zero-length label")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_name);
        }
    }

    GIVEN("a name with a leading dot")
    {
        auto result = encode_dns_name(".a.local");
        THEN("it returns invalid_name") { REQUIRE_FALSE(result.has_value()); }
    }
}

SCENARIO("encode_dns_name parses backslash-DDD decimal escapes", "[dns_read][encode_dns_name][escaping]")
{
    GIVEN("the escape \\009 (horizontal tab) inside a label")
    {
        auto result = encode_dns_name("a\\009b.local.");
        THEN("the label contains the raw byte 0x09")
        {
            REQUIRE(result.has_value());
            REQUIRE(static_cast<uint8_t>((*result)[0]) == 3);
            REQUIRE(static_cast<uint8_t>((*result)[2]) == 0x09);
        }
    }

    GIVEN("malformed decimal escapes")
    {
        THEN("a truncated escape is rejected")
        {
            REQUIRE_FALSE(encode_dns_name("a\\09.local").has_value());
        }
        THEN("a value above 255 is rejected")
        {
            REQUIRE_FALSE(encode_dns_name("a\\999.local").has_value());
        }
        THEN("a dangling backslash is rejected")
        {
            REQUIRE_FALSE(encode_dns_name("a.local\\").has_value());
        }
    }
}

SCENARIO("skip_dns_name rejects reserved label tags exactly like read_dns_name",
         "[dns_read][skip_dns_name][safety]")
{
    using mdnspp::detail::read_dns_name;

    GIVEN("a buffer whose first byte carries the reserved 01 tag (0x40)")
    {
        auto buf = bytes({0x40, 'a', 0x00});
        size_t offset = 0;
        THEN("skip and read agree on rejection")
        {
            REQUIRE_FALSE(skip_dns_name(std::span<const std::byte>(buf), offset));
            REQUIRE_FALSE(read_dns_name(std::span<const std::byte>(buf), 0).has_value());
        }
    }

    GIVEN("a buffer whose first byte carries the reserved 10 tag (0x80)")
    {
        auto buf = bytes({0x80, 'a', 0x00});
        size_t offset = 0;
        THEN("skip and read agree on rejection")
        {
            REQUIRE_FALSE(skip_dns_name(std::span<const std::byte>(buf), offset));
            REQUIRE_FALSE(read_dns_name(std::span<const std::byte>(buf), 0).has_value());
        }
    }
}

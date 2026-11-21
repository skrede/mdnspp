#include "helpers.h"

using mdnspp::service_txt;
using mdnspp::detail::encode_dns_name;

namespace {

void check_mixed_entries(const std::vector<std::byte> &result)
{
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
        // offset after the first entry: 1 + 7 = 8
        REQUIRE(static_cast<uint8_t>(result[8]) == 4); // "flag" = 4 chars
    }

    THEN("the oversized third entry is skipped entirely")
    {
        // only the first two entries are encoded: (1+7) + (1+4) = 13 bytes
        REQUIRE(result.size() == 13);
    }
}

void check_entry_length_boundary()
{
    GIVEN("a TXT entry with exactly 255 bytes")
    {
        std::string value(251, 'x');
        std::vector<service_txt> entries = {service_txt{std::string(1, 'k'), std::string(253, 'v')}}; // 255
        auto result = mdnspp::detail::encode_txt_records(entries);
        THEN("it is accepted at 255 bytes")
        {
            REQUIRE_FALSE(result.empty());
            REQUIRE(static_cast<uint8_t>(result[0]) == 255);
        }
    }

    GIVEN("a TXT entry with 256 bytes")
    {
        std::vector<service_txt> entries = {service_txt{std::string(1, 'k'), std::string(254, 'v')}}; // 256
        auto result = mdnspp::detail::encode_txt_records(entries);
        THEN("it is skipped, leaving the RFC 6763 §6.1 single zero byte")
        {
            REQUIRE(result.size() == 1);
            REQUIRE(result[0] == std::byte{0x00});
        }
    }
}

void check_single_label_bounds()
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
}

}

SCENARIO("encode_txt_records handles entry with value, entry without value, and oversized entry",
         "[response_detail][encode_txt_records]")
{
    GIVEN("a set of TXT entries including one >255 chars")
    {
        std::string long_value(300, 'x');
        std::vector<service_txt> entries = {
            service_txt{"key", "val"},
            service_txt{"flag", std::nullopt},
            service_txt{"big", long_value},
        };
        auto result = mdnspp::detail::encode_txt_records(entries);
        check_mixed_entries(result);
    }

    check_entry_length_boundary();

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

SCENARIO("encode_dns_name rejects labels exceeding 63 bytes", "[dns_read][encode_dns_name]")
{
    check_single_label_bounds();

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
        // wire: (1+63)+(1+63)+(1+63)+(1+61)+1 = 255
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

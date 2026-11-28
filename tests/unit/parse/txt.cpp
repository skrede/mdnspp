#include "helpers.h"

static std::vector<std::byte> key_val_and_flag_txt()
{
    return bytes({0x04, 'h','o','s','t', 0x00,         // owner "host."
                  0x07, 'k','e','y','=','v','a','l',   // "key=val" (length=7)
                  0x04, 'f','l','a','g'});             // "flag" (length=4, key-only)
}

static std::vector<std::byte> empty_string_between_entries_txt()
{
    return bytes({0x04, 'h', 'o', 's', 't', 0x00, // owner "host."
                  0x03, 'a', '=', '1',            // "a=1"
                  0x00,                           // zero-length string
                  0x03, 'b', '=', '2'});          // "b=2"
}

static void check_canonical_empty_txt()
{
    GIVEN("the canonical empty TXT record: a single zero-length string (RFC 6763 section 6.1)")
    {
        auto buf = bytes({0x04, 'h', 'o', 's', 't', 0x00, // owner "host."
                          0x00});                         // zero-length string
        auto meta = record_meta(dns_type::txt, 6, 1);

        WHEN("parse::txt is called")
        {
            auto result = parse::txt(std::span<const std::byte>(buf), meta);

            THEN("no phantom entry is produced (RFC 6763 section 6.4)")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_txt>(*result);
                REQUIRE(r.entries.empty());
            }
        }
    }
}

static void check_zero_length_between_entries()
{
    GIVEN("a zero-length string between two valid entries")
    {
        auto buf = empty_string_between_entries_txt();
        auto meta = record_meta(dns_type::txt, 6, buf.size() - 6);

        WHEN("parse::txt is called")
        {
            auto result = parse::txt(std::span<const std::byte>(buf), meta);

            THEN("only the two non-empty entries are collected")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_txt>(*result);
                REQUIRE(r.entries.size() == 2);
                REQUIRE(r.entries[0].key == "a");
                REQUIRE(r.entries[0].value == "1");
                REQUIRE(r.entries[1].key == "b");
                REQUIRE(r.entries[1].value == "2");
            }
        }
    }
}

SCENARIO("parse::txt collects all key-value pairs from TXT wire format", "[parse][txt]")
{
    GIVEN("a TXT record with two entries: 'key=val' and 'flag'")
    {
        auto buf = key_val_and_flag_txt();
        auto meta = record_meta(dns_type::txt, 6, buf.size() - 6);

        WHEN("parse::txt is called")
        {
            auto result = parse::txt(std::span<const std::byte>(buf), meta);

            THEN("entries vector has two items with correct key/value")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_txt>(*result);
                REQUIRE(r.entries.size() == 2);
                REQUIRE(r.entries[0].key == "key");
                REQUIRE(r.entries[0].value.has_value());
                REQUIRE(*r.entries[0].value == "val");
                REQUIRE(r.entries[1].key == "flag");
                REQUIRE_FALSE(r.entries[1].value.has_value());
            }
        }
    }
}

SCENARIO("parse::txt handles empty TXT record gracefully", "[parse][txt]")
{
    GIVEN("a TXT record with zero length (empty)")
    {
        auto buf = bytes({0x04, 'h', 'o', 's', 't', 0x00});
        auto meta = record_meta(dns_type::txt, 6, 0);

        WHEN("parse::txt is called")
        {
            auto result = parse::txt(std::span<const std::byte>(buf), meta);

            THEN("it returns record_txt with empty entries (not an error)")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_txt>(*result);
                REQUIRE(r.entries.empty());
            }
        }
    }
}

SCENARIO("parse::txt ignores zero-length TXT strings", "[parse][txt]")
{
    check_canonical_empty_txt();
    check_zero_length_between_entries();
}

SCENARIO("parse::txt returns error on truncated input", "[parse][txt][malformed]")
{
    GIVEN("a buffer shorter than record_length")
    {
        auto buf = bytes({0x07, 'k','e','y'});
        auto meta = record_meta(dns_type::txt, 0, 12);

        WHEN("parse::txt is called")
        {
            auto result = parse::txt(std::span<const std::byte>(buf), meta);

            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

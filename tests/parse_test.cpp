// tests/parse_test.cpp

#include "mdnspp/parse.h"
#include "mdnspp/records.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>

using namespace mdnspp;
using mdnspp::dns_type;
using mdnspp::dns_class;

// Helper: build a byte vector from initializer list of unsigned chars
static std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
{
    std::vector<std::byte> v;
    v.reserve(vals.size());
    for (auto b : vals)
        v.push_back(static_cast<std::byte>(b));
    return v;
}

// ---------------------------------------------------------------------------
// parse::a
// ---------------------------------------------------------------------------

SCENARIO("parse::a parses a valid A record", "[parse][a]")
{
    GIVEN("a 4-byte IPv4 address buffer representing 192.168.1.1")
    {
        auto buf = bytes({0xC0, 0xA8, 0x01, 0x01});

        record_metadata meta;
        meta.sender        = {"0.0.0.0", 0};
        meta.ttl           = 120;
        meta.rclass        = dns_class::in;
        meta.rtype         = dns_type::a; // A
        meta.name_offset   = 0;
        meta.record_offset = 0;
        meta.record_length = 4;

        WHEN("parse::a is called")
        {
            auto result = parse::a(std::span<const std::byte>(buf), meta);

            THEN("it returns record_a with correct address_string")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_a>(*result);
                REQUIRE(r.address_string == "192.168.1.1");
                REQUIRE(r.ttl == 120);
                REQUIRE(r.rclass == dns_class::in);
                REQUIRE(r.length == 4);
            }
        }
    }
}

SCENARIO("parse::a parses loopback address 127.0.0.1", "[parse][a]")
{
    GIVEN("a 4-byte buffer representing 127.0.0.1")
    {
        auto buf = bytes({0x7F, 0x00, 0x00, 0x01});

        record_metadata meta;
        meta.rtype         = dns_type::a;
        meta.record_offset = 0;
        meta.record_length = 4;

        WHEN("parse::a is called")
        {
            auto result = parse::a(std::span<const std::byte>(buf), meta);

            THEN("it returns record_a with address_string 127.0.0.1")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_a>(*result);
                REQUIRE(r.address_string == "127.0.0.1");
            }
        }
    }
}

SCENARIO("parse::a returns error on truncated input", "[parse][a][malformed]")
{
    GIVEN("a buffer shorter than record_length (2 bytes for a 4-byte record)")
    {
        auto buf = bytes({0xC0, 0xA8});

        record_metadata meta;
        meta.record_offset = 0;
        meta.record_length = 4;
        meta.rtype         = dns_type::a;

        WHEN("parse::a is called")
        {
            auto result = parse::a(std::span<const std::byte>(buf), meta);

            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("parse::a returns error when record_length is not 4", "[parse][a][malformed]")
{
    GIVEN("a buffer with record_length=5 (invalid for A record)")
    {
        auto buf = bytes({0xC0, 0xA8, 0x01, 0x01, 0x00});

        record_metadata meta;
        meta.record_offset = 0;
        meta.record_length = 5;
        meta.rtype         = dns_type::a;

        WHEN("parse::a is called")
        {
            auto result = parse::a(std::span<const std::byte>(buf), meta);

            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// parse::aaaa
// ---------------------------------------------------------------------------

SCENARIO("parse::aaaa parses a valid AAAA record", "[parse][aaaa]")
{
    GIVEN("a 16-byte IPv6 address buffer representing ::1")
    {
        // ::1 in network byte order = 15 zeroes + 0x01
        auto buf = bytes({
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01
        });

        record_metadata meta;
        meta.rtype         = dns_type::aaaa; // AAAA
        meta.record_offset = 0;
        meta.record_length = 16;

        WHEN("parse::aaaa is called")
        {
            auto result = parse::aaaa(std::span<const std::byte>(buf), meta);

            THEN("it returns record_aaaa with a non-empty address_string")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_aaaa>(*result);
                REQUIRE_FALSE(r.address_string.empty());
                REQUIRE(r.length == 16);
            }
        }
    }
}

SCENARIO("parse::aaaa returns error on truncated input", "[parse][aaaa][malformed]")
{
    GIVEN("a buffer of only 8 bytes for a 16-byte AAAA record")
    {
        auto buf = bytes({
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        });

        record_metadata meta;
        meta.record_offset = 0;
        meta.record_length = 16;
        meta.rtype         = dns_type::aaaa;

        WHEN("parse::aaaa is called")
        {
            auto result = parse::aaaa(std::span<const std::byte>(buf), meta);

            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("parse::aaaa returns error when record_length is not 16", "[parse][aaaa][malformed]")
{
    GIVEN("a buffer with record_length=4 (wrong for AAAA)")
    {
        auto buf = bytes({0x00, 0x00, 0x00, 0x01});

        record_metadata meta;
        meta.record_offset = 0;
        meta.record_length = 4;
        meta.rtype         = dns_type::aaaa;

        WHEN("parse::aaaa is called")
        {
            auto result = parse::aaaa(std::span<const std::byte>(buf), meta);

            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// parse::ptr
// ---------------------------------------------------------------------------

SCENARIO("parse::ptr parses a valid PTR record", "[parse][ptr]")
{
    GIVEN("a DNS wire buffer with a PTR record pointing to _http._tcp.local.")
    {
        // DNS labels: 5 "_http" 4 "_tcp" 5 "local" 0
        // We put the PTR target at the start of the buffer (record_offset = 0)
        // and use name_offset = 0 so name extraction also reads from the start.
        auto buf = bytes({
            0x05, '_','h','t','t','p',
            0x04, '_','t','c','p',
            0x05, 'l','o','c','a','l',
            0x00
        });

        record_metadata meta;
        meta.rtype         = dns_type::ptr; // PTR
        meta.name_offset   = 0;
        meta.record_offset = 0;
        meta.record_length = static_cast<size_t>(buf.size());

        WHEN("parse::ptr is called")
        {
            auto result = parse::ptr(std::span<const std::byte>(buf), meta);

            THEN("it returns record_ptr with non-empty ptr_name")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_ptr>(*result);
                REQUIRE_FALSE(r.ptr_name.empty());
                // The PTR name should contain "_http._tcp.local."
                REQUIRE(r.ptr_name.find("_http") != std::string::npos);
            }
        }
    }
}

SCENARIO("parse::ptr returns error on truncated input", "[parse][ptr][malformed]")
{
    GIVEN("a buffer shorter than record_length")
    {
        auto buf = bytes({0x05, '_','h','t','t','p'});  // only 6 bytes

        record_metadata meta;
        meta.rtype         = dns_type::ptr;
        meta.record_offset = 0;
        meta.record_length = 20; // claims 20 bytes but buffer has only 6

        WHEN("parse::ptr is called")
        {
            auto result = parse::ptr(std::span<const std::byte>(buf), meta);

            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// parse::srv
// ---------------------------------------------------------------------------

SCENARIO("parse::srv parses a valid SRV record", "[parse][srv]")
{
    GIVEN("a DNS wire buffer with a SRV record (port 8080, priority 0, weight 0)")
    {
        // SRV format: priority(2) + weight(2) + port(2) + target-name
        // port 8080 = 0x1F90
        // target: "host.local." as DNS labels
        auto buf = bytes({
            0x00, 0x00,  // priority = 0
            0x00, 0x00,  // weight = 0
            0x1F, 0x90,  // port = 8080
            0x04, 'h','o','s','t',
            0x05, 'l','o','c','a','l',
            0x00
        });

        record_metadata meta;
        meta.rtype         = dns_type::srv; // SRV
        meta.name_offset   = 0;
        meta.record_offset = 0;
        meta.record_length = static_cast<size_t>(buf.size());

        WHEN("parse::srv is called")
        {
            auto result = parse::srv(std::span<const std::byte>(buf), meta);

            THEN("it returns record_srv with correct port, priority, weight and srv_name")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_srv>(*result);
                REQUIRE(r.port == 8080);
                REQUIRE(r.priority == 0);
                REQUIRE(r.weight == 0);
                REQUIRE_FALSE(r.srv_name.empty());
                REQUIRE(r.srv_name.find("host") != std::string::npos);
            }
        }
    }
}

SCENARIO("parse::srv returns error on truncated input", "[parse][srv][malformed]")
{
    GIVEN("a buffer with insufficient bytes for the claimed record_length")
    {
        auto buf = bytes({0x00, 0x00, 0x1F}); // only 3 bytes

        record_metadata meta;
        meta.rtype         = dns_type::srv;
        meta.record_offset = 0;
        meta.record_length = 20;

        WHEN("parse::srv is called")
        {
            auto result = parse::srv(std::span<const std::byte>(buf), meta);

            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// parse::txt
// ---------------------------------------------------------------------------

SCENARIO("parse::txt collects all key-value pairs from TXT wire format", "[parse][txt]")
{
    GIVEN("a TXT record with two entries: 'key=val' and 'flag'")
    {
        // DNS TXT format: [len][data] repeated; len = length of the string
        // "key=val" = 7 bytes, "flag" = 4 bytes (key-only, no '=')
        auto buf = bytes({
            0x07, 'k','e','y','=','v','a','l',   // "key=val" (length=7)
            0x04, 'f','l','a','g'                // "flag" (length=4, key-only)
        });

        record_metadata meta;
        meta.rtype         = dns_type::txt; // TXT
        meta.name_offset   = 0;
        meta.record_offset = 0;
        meta.record_length = static_cast<size_t>(buf.size());

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
        auto buf = bytes({});

        record_metadata meta;
        meta.rtype         = dns_type::txt;
        meta.record_offset = 0;
        meta.record_length = 0;

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

SCENARIO("parse::txt returns error on truncated input", "[parse][txt][malformed]")
{
    GIVEN("a buffer shorter than record_length")
    {
        auto buf = bytes({0x07, 'k','e','y'}); // only 4 bytes, claims 12

        record_metadata meta;
        meta.rtype         = dns_type::txt;
        meta.record_offset = 0;
        meta.record_length = 12;

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

// ---------------------------------------------------------------------------
// parse::record (dispatch)
// ---------------------------------------------------------------------------

SCENARIO("parse::record dispatches to parse::a for rtype=1", "[parse][dispatch]")
{
    GIVEN("an A record buffer (rtype=1)")
    {
        auto buf = bytes({0x7F, 0x00, 0x00, 0x01}); // 127.0.0.1

        record_metadata meta;
        meta.rtype         = dns_type::a;
        meta.record_offset = 0;
        meta.record_length = 4;

        WHEN("parse::record is called")
        {
            auto result = parse::record(std::span<const std::byte>(buf), meta);

            THEN("it returns a record_a variant alternative")
            {
                REQUIRE(result.has_value());
                REQUIRE(std::holds_alternative<record_a>(*result));
            }
        }
    }
}

SCENARIO("parse::record dispatches to parse::aaaa for rtype=28", "[parse][dispatch]")
{
    GIVEN("an AAAA record buffer (rtype=28) for ::1")
    {
        auto buf = bytes({
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01
        });

        record_metadata meta;
        meta.rtype         = dns_type::aaaa;
        meta.record_offset = 0;
        meta.record_length = 16;

        WHEN("parse::record is called")
        {
            auto result = parse::record(std::span<const std::byte>(buf), meta);

            THEN("it returns a record_aaaa variant alternative")
            {
                REQUIRE(result.has_value());
                REQUIRE(std::holds_alternative<record_aaaa>(*result));
            }
        }
    }
}

SCENARIO("parse::record returns error for unknown rtype", "[parse][dispatch][malformed]")
{
    GIVEN("a metadata with unknown rtype=255")
    {
        auto buf = bytes({0x00});

        record_metadata meta;
        meta.rtype         = dns_type::any;
        meta.record_offset = 0;
        meta.record_length = 1;

        WHEN("parse::record is called")
        {
            auto result = parse::record(std::span<const std::byte>(buf), meta);

            THEN("it returns parse_error")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

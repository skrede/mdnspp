#include "helpers.h"

SCENARIO("parse::a parses a valid A record", "[parse][a]")
{
    GIVEN("an owner name followed by a 4-byte IPv4 address representing 192.168.1.1")
    {
        auto buf = host_a_record(0xC0, 0xA8, 0x01, 0x01);
        record_metadata meta{.sender = {"0.0.0.0", 0}, .ttl = 120, .rclass = dns_class::in, .rtype = dns_type::a,
                             .name_offset = 0, .record_offset = 6, .record_length = 4};

        WHEN("parse::a is called")
        {
            auto result = parse::a(std::span<const std::byte>(buf), meta);

            THEN("it returns record_a with correct address_string")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_a>(*result);
                REQUIRE(r.name == "host.");
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
    GIVEN("an owner name followed by a 4-byte buffer representing 127.0.0.1")
    {
        auto buf = host_a_record(0x7F, 0x00, 0x00, 0x01);
        auto meta = record_meta(dns_type::a, 6, 4);

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
        auto meta = record_meta(dns_type::a, 0, 4);

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
        auto meta = record_meta(dns_type::a, 0, 5);

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

SCENARIO("parse::aaaa parses a valid AAAA record", "[parse][aaaa]")
{
    GIVEN("a 16-byte IPv6 address buffer representing ::1")
    {
        auto buf = ipv6_loopback();
        auto meta = record_meta(dns_type::aaaa, 0, 16);

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
        auto buf = bytes({0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00});
        auto meta = record_meta(dns_type::aaaa, 0, 16);

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
        auto meta = record_meta(dns_type::aaaa, 0, 4);

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

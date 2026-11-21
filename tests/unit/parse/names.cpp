#include "helpers.h"

static std::vector<std::byte> srv_rdata()
{
    return bytes({0x00, 0x00,               // priority = 0
                  0x00, 0x00,               // weight = 0
                  0x1F, 0x90,               // port = 8080
                  0x04, 'h','o','s','t',    // target "host.local."
                  0x05, 'l','o','c','a','l',
                  0x00});
}

SCENARIO("parse::ptr parses a valid PTR record", "[parse][ptr]")
{
    GIVEN("a DNS wire buffer with a PTR record pointing to _http._tcp.local.")
    {
        auto buf = bytes({0x05, '_','h','t','t','p',
                          0x04, '_','t','c','p',
                          0x05, 'l','o','c','a','l',
                          0x00});
        auto meta = record_meta(dns_type::ptr, 0, buf.size());

        WHEN("parse::ptr is called")
        {
            auto result = parse::ptr(std::span<const std::byte>(buf), meta);

            THEN("it returns record_ptr with non-empty ptr_name")
            {
                REQUIRE(result.has_value());
                auto &r = std::get<record_ptr>(*result);
                REQUIRE_FALSE(r.ptr_name.empty());
                REQUIRE(r.ptr_name.find("_http") != dns_name::npos);
            }
        }
    }
}

SCENARIO("parse::ptr returns error on truncated input", "[parse][ptr][malformed]")
{
    GIVEN("a buffer shorter than record_length")
    {
        auto buf = bytes({0x05, '_','h','t','t','p'});
        auto meta = record_meta(dns_type::ptr, 0, 20);

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

SCENARIO("parse::srv parses a valid SRV record", "[parse][srv]")
{
    GIVEN("a DNS wire buffer with a SRV record (port 8080, priority 0, weight 0)")
    {
        auto buf = srv_rdata();
        auto meta = record_meta(dns_type::srv, 0, buf.size());

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
                REQUIRE(r.srv_name.find("host") != dns_name::npos);
            }
        }
    }
}

SCENARIO("parse::srv returns error on truncated input", "[parse][srv][malformed]")
{
    GIVEN("a buffer with insufficient bytes for the claimed record_length")
    {
        auto buf = bytes({0x00, 0x00, 0x1F});
        auto meta = record_meta(dns_type::srv, 0, 20);

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

SCENARIO("parse rejects records with a malformed owner name", "[parse][owner][malformed]")
{
    GIVEN("an A record whose owner name has an oversized label")
    {
        // Label length 0x7F exceeds the RFC 1035 63-octet limit
        auto buf = bytes({0x7F, 'x', 0x00,
                          0xC0, 0xA8, 0x01, 0x01});
        auto meta = record_meta(dns_type::a, 3, 4);

        WHEN("parse::a is called")
        {
            auto result = parse::a(std::span<const std::byte>(buf), meta);

            THEN("the record is rejected instead of receiving an empty owner name")
            {
                REQUIRE_FALSE(result.has_value());
                REQUIRE(result.error() == mdns_error::parse_error);
            }
        }
    }
}

SCENARIO("parse::ptr bounds rdata name reads to the record extent", "[parse][ptr][bounds]")
{
    GIVEN("a PTR record whose rdata name runs past record_length into trailing bytes")
    {
        auto buf = bytes({0x01, 'a', 0x00,    // owner
                          0x02, 'b', 'c',     // rdata: label, unterminated
                          0x00});             // terminator OUTSIDE the record
        auto meta = record_meta(dns_type::ptr, 3, 3);

        WHEN("parse::ptr is called")
        {
            auto result = parse::ptr(std::span<const std::byte>(buf), meta);

            THEN("the read is bounded and the record rejected")
            {
                REQUIRE_FALSE(result.has_value());
            }
        }
    }
}

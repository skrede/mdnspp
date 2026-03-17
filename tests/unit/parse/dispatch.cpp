#include "helpers.h"

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

// ---------------------------------------------------------------------------
// cache-flush bit propagation
// ---------------------------------------------------------------------------

// Helper: build a minimal DNS response with one A record.
// rclass_raw is the raw 16-bit class value (0x8001 = cache-flush + IN, 0x0001 = plain IN).
static std::vector<std::byte> make_a_response(uint16_t rclass_raw)
{
    // DNS header: id=0, flags=0x8400 (response, authoritative), 0 questions, 1 answer, 0 ns, 0 ar
    // Answer RR: name = single label "h" (0x01 'h' 0x00), type A (0x0001),
    //            class = rclass_raw, TTL = 120, rdlength = 4, rdata = 192.168.1.1
    return bytes({
        // --- header (12 bytes) ---
        0x00, 0x00,  // ID
        0x84, 0x00,  // flags
        0x00, 0x00,  // qdcount = 0
        0x00, 0x01,  // ancount = 1
        0x00, 0x00,  // nscount = 0
        0x00, 0x00,  // arcount = 0
        // --- answer RR ---
        0x01, 'h', 0x00,                                            // name: "h."
        0x00, 0x01,                                                  // type A
        static_cast<unsigned char>((rclass_raw >> 8) & 0xFF),
        static_cast<unsigned char>(rclass_raw & 0xFF),               // class
        0x00, 0x00, 0x00, 0x78,                                     // TTL = 120
        0x00, 0x04,                                                  // rdlength = 4
        0xC0, 0xA8, 0x01, 0x01                                      // 192.168.1.1
    });
}

SCENARIO("walk_dns_frame propagates cache_flush=true when cache-flush bit is set", "[parse][cache_flush]")
{
    GIVEN("a DNS response with rclass = 0x8001 (cache-flush + IN)")
    {
        auto buf = make_a_response(0x8001);

        WHEN("walk_dns_frame is called")
        {
            std::vector<mdns_record_variant> records;
            detail::walk_dns_frame(
                std::span<const std::byte>(buf),
                endpoint{"10.0.0.1", 5353},
                [&](mdns_record_variant rec) { records.push_back(std::move(rec)); });

            THEN("the parsed A record has cache_flush=true and rclass=IN")
            {
                REQUIRE(records.size() == 1);
                auto &r = std::get<record_a>(records[0]);
                REQUIRE(r.cache_flush == true);
                REQUIRE(r.rclass == dns_class::in);
            }
        }
    }
}

SCENARIO("walk_dns_frame propagates cache_flush=false when cache-flush bit is clear", "[parse][cache_flush]")
{
    GIVEN("a DNS response with rclass = 0x0001 (plain IN)")
    {
        auto buf = make_a_response(0x0001);

        WHEN("walk_dns_frame is called")
        {
            std::vector<mdns_record_variant> records;
            detail::walk_dns_frame(
                std::span<const std::byte>(buf),
                endpoint{"10.0.0.1", 5353},
                [&](mdns_record_variant rec) { records.push_back(std::move(rec)); });

            THEN("the parsed A record has cache_flush=false and rclass=IN")
            {
                REQUIRE(records.size() == 1);
                auto &r = std::get<record_a>(records[0]);
                REQUIRE(r.cache_flush == false);
                REQUIRE(r.rclass == dns_class::in);
            }
        }
    }
}

SCENARIO("cache_flush field defaults to false on all record types", "[parse][cache_flush]")
{
    GIVEN("default-constructed record structs")
    {
        THEN("cache_flush is false")
        {
            REQUIRE(record_ptr{}.cache_flush == false);
            REQUIRE(record_srv{}.cache_flush == false);
            REQUIRE(record_a{}.cache_flush == false);
            REQUIRE(record_aaaa{}.cache_flush == false);
            REQUIRE(record_txt{}.cache_flush == false);
        }
    }
}

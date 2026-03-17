// Unit tests for build_dns_response round-trip via walk_dns_frame,
// and cache-flush bit verification on raw wire bytes.

#include "helpers.h"

using mdnspp::detail::build_dns_response;
using mdnspp::detail::walk_dns_frame;
using mdnspp::detail::encode_dns_name;
using mdnspp::detail::skip_dns_name;
using mdnspp::detail::read_u16_be;

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

SCENARIO("build_dns_response produces valid AAAA response", "[build_dns_response][AAAA]")
{
    GIVEN("a service_info with address_ipv6 = \"::1\"")
    {
        auto info = make_test_service_v46();

        WHEN("build_dns_response is called with qtype=28 (AAAA)")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::aaaa, mdnspp::service_options{});

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
            auto pkt = build_dns_response(info, mdnspp::dns_type::aaaa, mdnspp::service_options{});

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
            auto pkt = build_dns_response(info, mdnspp::dns_type::any, mdnspp::service_options{});

            THEN("the packet is non-empty and arcount is 0")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t arcount = read_u16_be(pkt, 10);
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
            auto pkt = build_dns_response(info, mdnspp::dns_type::txt, mdnspp::service_options{});

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
            auto pkt = build_dns_response(info, mdnspp::dns_type::ptr, mdnspp::service_options{});

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
// Cache-flush bit tests — verify raw wire bytes (not walk_dns_frame which strips the bit)
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response PTR answer does NOT have cache-flush bit set", "[build_dns_response][cache_flush]")
{
    GIVEN("a service_info with both addresses")
    {
        auto info = make_test_service_v46();

        WHEN("build_dns_response is called with qtype=PTR")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::ptr, mdnspp::service_options{});

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
            auto pkt = build_dns_response(info, mdnspp::dns_type::srv, mdnspp::service_options{});

            THEN("the first RR (SRV answer) has rrclass 0x8001 (cache-flush bit set)")
            {
                uint16_t rrclass = find_first_rr_rrclass(pkt);
                REQUIRE(rrclass == 0x8001);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Error handling: invalid address encoding
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response ANY omits A record for invalid IPv4 address",
         "[build_dns_response][error_handling][ipv4]")
{
    GIVEN("a service_info with an invalid IPv4 address and valid IPv6 address")
    {
        auto info = make_test_service_v46();
        info.address_ipv4 = "999.1.2.3";  // intentionally malformed

        WHEN("build_dns_response is called with qtype=ANY")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::any, mdnspp::service_options{});

            THEN("the packet is non-empty (other records are present)")
            {
                REQUIRE_FALSE(pkt.empty());
            }

            THEN("walk_dns_frame finds no A record but does find SRV, PTR, and AAAA records")
            {
                auto records = parse_wire(pkt);
                bool has_a = false, has_srv = false, has_ptr = false, has_aaaa = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<mdnspp::record_a>(rv)) has_a = true;
                    if(std::holds_alternative<mdnspp::record_srv>(rv)) has_srv = true;
                    if(std::holds_alternative<mdnspp::record_ptr>(rv)) has_ptr = true;
                    if(std::holds_alternative<mdnspp::record_aaaa>(rv)) has_aaaa = true;
                }
                REQUIRE_FALSE(has_a);
                REQUIRE(has_srv);
                REQUIRE(has_ptr);
                REQUIRE(has_aaaa);
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
            auto pkt = build_dns_response(info, mdnspp::dns_type::any, mdnspp::service_options{});

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

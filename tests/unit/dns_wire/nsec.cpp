// Unit tests for build_probe_query, build_nsec_bitmap, and append_nsec_rr.

#include "helpers.h"

using mdnspp::detail::build_dns_response;
using mdnspp::detail::walk_dns_frame;
using mdnspp::detail::encode_dns_name;
using mdnspp::detail::skip_dns_name;
using mdnspp::detail::build_probe_query;
using mdnspp::detail::build_nsec_bitmap;
using mdnspp::detail::append_nsec_rr;
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

// ---------------------------------------------------------------------------
// build_probe_query tests
// ---------------------------------------------------------------------------

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

                REQUIRE(qtype == mdnspp::detail::to_underlying(mdnspp::dns_type::any));
                REQUIRE(qclass == 0x8001);
            }

            THEN("the authority section contains an SRV record")
            {
                auto rrs = collect_rr_type_class(pkt);
                REQUIRE(rrs.size() == 1);
                REQUIRE(rrs[0].first == mdnspp::detail::to_underlying(mdnspp::dns_type::srv));
            }

            THEN("the question name matches the service_name")
            {
                auto result = mdnspp::detail::read_dns_name(
                    std::span<const std::byte>(pkt), 12);
                REQUIRE(result.has_value());
                REQUIRE(*result == "myservice._http._tcp.local.");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NSEC bitmap and record tests
// ---------------------------------------------------------------------------

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

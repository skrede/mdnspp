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
using mdnspp::detail::nsec_owner;

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

SCENARIO("build_probe_query probes all proposed names with the full record set in authority", "[build_probe_query]")
{
    GIVEN("a test service_info with IPv4 and IPv6 addresses")
    {
        auto info = make_test_service_v46();

        WHEN("build_probe_query is called")
        {
            auto pkt = build_probe_query(info);

            THEN("the header has id=0, flags=0x0000, qdcount=2, nscount=4")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t id = read_u16_be(pkt.data());
                uint16_t flags = read_u16_be(pkt.data() + 2);
                uint16_t qdcount = read_u16_be(pkt.data() + 4);
                uint16_t ancount = read_u16_be(pkt.data() + 6);
                uint16_t nscount = read_u16_be(pkt.data() + 8);

                REQUIRE(id == 0); // RFC 6762 section 18.1
                REQUIRE(flags == 0x0000);
                REQUIRE(qdcount == 2); // service_name + hostname (RFC 6762 section 8.1)
                REQUIRE(ancount == 0);
                REQUIRE(nscount == 4); // SRV + TXT + A + AAAA
            }

            THEN("both questions have QTYPE=ANY and QCLASS=0x8001 (QU bit)")
            {
                size_t offset = 12;
                auto span = std::span<const std::byte>(pkt);
                for(int q = 0; q < 2; ++q)
                {
                    skip_dns_name(span, offset);
                    uint16_t qtype = read_u16_be(pkt.data() + offset);
                    uint16_t qclass = read_u16_be(pkt.data() + offset + 2);
                    REQUIRE(qtype == mdnspp::detail::to_underlying(mdnspp::dns_type::any));
                    REQUIRE(qclass == 0x8001);
                    offset += 4;
                }
            }

            THEN("the authority section contains SRV, TXT, A and AAAA records")
            {
                auto rrs = collect_rr_type_class(pkt);
                REQUIRE(rrs.size() == 4);
                REQUIRE(rrs[0].first == mdnspp::detail::to_underlying(mdnspp::dns_type::srv));
                REQUIRE(rrs[1].first == mdnspp::detail::to_underlying(mdnspp::dns_type::txt));
                REQUIRE(rrs[2].first == mdnspp::detail::to_underlying(mdnspp::dns_type::a));
                REQUIRE(rrs[3].first == mdnspp::detail::to_underlying(mdnspp::dns_type::aaaa));
            }

            THEN("the first question name matches the service_name and the second the hostname")
            {
                auto span = std::span<const std::byte>(pkt);
                auto first = mdnspp::detail::read_dns_name(span, 12);
                REQUIRE(first.has_value());
                REQUIRE(*first == "MyService._http._tcp.local.");

                size_t offset = 12;
                skip_dns_name(span, offset);
                offset += 4;
                auto second = mdnspp::detail::read_dns_name(span, offset);
                REQUIRE(second.has_value());
                REQUIRE(*second == "myhost.local.");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// NSEC bitmap and record tests (RFC 6762 section 6.1: the bitmap lists the
// types that DO exist at the owner name)
// ---------------------------------------------------------------------------

SCENARIO("build_nsec_bitmap for the hostname lists only the configured address types", "[nsec][bitmap]")
{
    GIVEN("a service_info with only address_ipv4 set")
    {
        auto info = make_test_service_v46();
        info.address_ipv6 = std::nullopt;

        WHEN("build_nsec_bitmap is called with owner=hostname")
        {
            auto bitmap = build_nsec_bitmap(nsec_owner::hostname, info);

            THEN("the bitmap has window=0x00, length=1, only the A(1) bit")
            {
                REQUIRE(bitmap.size() == 3); // 2 header + 1 bitmap byte
                REQUIRE(bitmap[0] == std::byte{0x00}); // window
                REQUIRE(bitmap[1] == std::byte{0x01}); // length
                REQUIRE(bitmap[2] == std::byte{0x40}); // A(1)
            }
        }
    }

    GIVEN("a service_info with both address_ipv4 and address_ipv6 set")
    {
        auto info = make_test_service_v46();

        WHEN("build_nsec_bitmap is called with owner=hostname")
        {
            auto bitmap = build_nsec_bitmap(nsec_owner::hostname, info);

            THEN("the bitmap covers A(1) and AAAA(28)")
            {
                REQUIRE(bitmap.size() == 6); // 2 header + 4 bitmap bytes
                REQUIRE(bitmap[1] == std::byte{0x04}); // length
                REQUIRE(bitmap[2] == std::byte{0x40}); // A(1)
                REQUIRE(bitmap[3] == std::byte{0x00});
                REQUIRE(bitmap[4] == std::byte{0x00});
                REQUIRE(bitmap[5] == std::byte{0x08}); // AAAA(28)
            }
        }
    }

    GIVEN("a service_info with no address fields set")
    {
        auto info = make_test_service_v46();
        info.address_ipv4 = std::nullopt;
        info.address_ipv6 = std::nullopt;

        WHEN("build_nsec_bitmap is called with owner=hostname")
        {
            auto bitmap = build_nsec_bitmap(nsec_owner::hostname, info);

            THEN("the result is empty (no types exist, no valid NSEC)")
            {
                REQUIRE(bitmap.empty());
            }
        }
    }
}

SCENARIO("build_nsec_bitmap for the instance name lists SRV, TXT and NSEC", "[nsec][bitmap]")
{
    GIVEN("a service_info")
    {
        auto info = make_test_service_v46();

        WHEN("build_nsec_bitmap is called with owner=service_name")
        {
            auto bitmap = build_nsec_bitmap(nsec_owner::service_name, info);

            THEN("the bitmap flags TXT(16), SRV(33) and NSEC(47)")
            {
                REQUIRE(bitmap.size() == 8); // 2 header + 6 bitmap bytes
                REQUIRE(bitmap[1] == std::byte{0x06}); // length
                REQUIRE(bitmap[2] == std::byte{0x00});
                REQUIRE(bitmap[3] == std::byte{0x00});
                REQUIRE(bitmap[4] == std::byte{0x80}); // TXT(16)
                REQUIRE(bitmap[5] == std::byte{0x00});
                REQUIRE(bitmap[6] == std::byte{0x40}); // SRV(33)
                REQUIRE(bitmap[7] == std::byte{0x01}); // NSEC(47)
            }
        }
    }
}

SCENARIO("build_nsec_bitmap for the service type lists only PTR", "[nsec][bitmap]")
{
    GIVEN("a service_info")
    {
        auto info = make_test_service_v46();

        WHEN("build_nsec_bitmap is called with owner=service_type")
        {
            auto bitmap = build_nsec_bitmap(nsec_owner::service_type, info);

            THEN("the bitmap flags only PTR(12)")
            {
                REQUIRE(bitmap.size() == 4); // 2 header + 2 bitmap bytes
                REQUIRE(bitmap[1] == std::byte{0x02}); // length
                REQUIRE(bitmap[2] == std::byte{0x00});
                REQUIRE(bitmap[3] == std::byte{0x08}); // PTR(12)
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

        auto owner_name = encode_dns_name(info.hostname).value();

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

            append_nsec_rr(packet, owner_name, nsec_owner::hostname, info, 4500);

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
                auto expected_bitmap = build_nsec_bitmap(nsec_owner::hostname, info);
                REQUIRE(rdlength == owner_name.size() + expected_bitmap.size());
            }
        }
    }
}

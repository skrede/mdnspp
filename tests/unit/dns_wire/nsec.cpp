#include "helpers.h"

using mdnspp::detail::encode_dns_name;
using mdnspp::detail::skip_dns_name;
using mdnspp::detail::build_nsec_bitmap;
using mdnspp::detail::append_nsec_rr;
using mdnspp::detail::read_u16_be;
using mdnspp::detail::nsec_owner;

static void check_hostname_ipv4_only()
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
}

static void check_hostname_dual_stack()
{
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
}

static std::vector<std::byte> nsec_answer_packet(const std::vector<std::byte> &owner_name,
                                                 const mdnspp::service_info &info)
{
    std::vector<std::byte> packet;
    mdnspp::detail::push_u16_be(packet, 0x0000); // id
    mdnspp::detail::push_u16_be(packet, 0x8400); // flags
    mdnspp::detail::push_u16_be(packet, 0x0000); // qdcount
    mdnspp::detail::push_u16_be(packet, 0x0001); // ancount
    mdnspp::detail::push_u16_be(packet, 0x0000); // nscount
    mdnspp::detail::push_u16_be(packet, 0x0000); // arcount
    append_nsec_rr(packet, owner_name, nsec_owner::hostname, info, 4500);
    return packet;
}

static void check_nsec_rr(const std::vector<std::byte> &packet, const std::vector<std::byte> &owner_name,
                          const mdnspp::service_info &info)
{
    THEN("the RR has type=47, class=IN, correct TTL and rdata containing owner name + bitmap")
    {
        std::size_t offset = 12;
        skip_dns_name(std::span<const std::byte>(packet), offset);
        uint16_t rtype = read_u16_be(packet.data() + offset);
        uint16_t rclass = read_u16_be(packet.data() + offset + 2);
        uint32_t ttl = mdnspp::detail::read_u32_be(packet.data() + offset + 4);
        uint16_t rdlength = read_u16_be(packet.data() + offset + 8);

        REQUIRE(rtype == 47);
        REQUIRE(rclass == 0x0001); // no cache-flush
        REQUIRE(ttl == 4500);

        auto expected_bitmap = build_nsec_bitmap(nsec_owner::hostname, info);
        REQUIRE(rdlength == owner_name.size() + expected_bitmap.size());
    }
}

// RFC 6762 section 6.1: the bitmap lists the types that do exist at the owner name.
SCENARIO("build_nsec_bitmap for the hostname lists only the configured address types", "[nsec][bitmap]")
{
    check_hostname_ipv4_only();
    check_hostname_dual_stack();

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
            auto packet = nsec_answer_packet(owner_name, info);
            check_nsec_rr(packet, owner_name, info);
        }
    }
}

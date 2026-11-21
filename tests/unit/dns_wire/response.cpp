#include "helpers.h"

#include <algorithm>

using mdnspp::detail::build_dns_response;

template <typename Record>
static bool contains_record(const std::vector<mdnspp::mdns_record_variant> &records)
{
    return std::ranges::any_of(records, [](const auto &rv) { return std::holds_alternative<Record>(rv); });
}

static void check_any_records(const std::vector<std::byte> &pkt)
{
    THEN("walk_dns_frame parses PTR, SRV, A, AAAA, and TXT records")
    {
        auto records = parse_wire(pkt);
        REQUIRE(contains_record<mdnspp::record_ptr>(records));
        REQUIRE(contains_record<mdnspp::record_srv>(records));
        REQUIRE(contains_record<mdnspp::record_a>(records));
        REQUIRE(contains_record<mdnspp::record_aaaa>(records));
        REQUIRE(contains_record<mdnspp::record_txt>(records));
    }
}

static void check_any_without_a(const std::vector<std::byte> &pkt)
{
    THEN("walk_dns_frame finds no A record but does find SRV, PTR, and AAAA records")
    {
        auto records = parse_wire(pkt);
        REQUIRE_FALSE(contains_record<mdnspp::record_a>(records));
        REQUIRE(contains_record<mdnspp::record_srv>(records));
        REQUIRE(contains_record<mdnspp::record_ptr>(records));
        REQUIRE(contains_record<mdnspp::record_aaaa>(records));
    }
}

static void check_txt_rdata(const std::vector<std::byte> &pkt)
{
    THEN("the TXT rdata is one zero byte, not RDLENGTH=0 (RFC 6763 §6.1)")
    {
        auto span = std::span<const std::byte>(pkt);
        std::size_t offset = 12;
        REQUIRE(mdnspp::detail::skip_dns_name(span, offset));
        uint16_t rtype = read_u16_be(pkt, offset);
        REQUIRE(rtype == mdnspp::detail::to_underlying(mdnspp::dns_type::txt));
        uint16_t rdlength = read_u16_be(pkt, offset + 8);
        REQUIRE(rdlength == 1);
        REQUIRE(pkt[offset + 10] == std::byte{0x00});
    }
}

static void check_empty_txt_answer()
{
    GIVEN("a service_info with empty txt_records")
    {
        auto info = make_test_service_v46();
        info.txt_records.clear();

        WHEN("build_dns_response is called with qtype=16 (TXT)")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::txt, mdnspp::service_options{});

            THEN("the packet is non-empty")
            {
                REQUIRE_FALSE(pkt.empty());
            }

            check_txt_rdata(pkt);
        }
    }
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
                REQUIRE(contains_record<mdnspp::record_aaaa>(records));
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

            check_any_records(pkt);
        }
    }
}

SCENARIO("build_dns_response TXT with empty txt_records encodes a single zero byte", "[build_dns_response][TXT][empty]")
{
    check_empty_txt_answer();

    GIVEN("a service_info with empty txt_records queried as PTR")
    {
        auto info = make_test_service_v46();
        info.txt_records.clear();

        WHEN("build_dns_response is called with qtype=12 (PTR)")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::ptr, mdnspp::service_options{});

            THEN("the TXT record is still included (mandatory for DNS-SD instances)")
            {
                auto records = parse_wire(pkt);
                REQUIRE(contains_record<mdnspp::record_txt>(records));
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
                REQUIRE(contains_record<mdnspp::record_aaaa>(records));
            }
        }
    }
}

SCENARIO("build_dns_response ANY omits A record for invalid IPv4 address",
         "[build_dns_response][error_handling][ipv4]")
{
    GIVEN("a service_info with an invalid IPv4 address and valid IPv6 address")
    {
        auto info = make_test_service_v46();
        info.address_ipv4 = "999.1.2.3";

        WHEN("build_dns_response is called with qtype=ANY")
        {
            auto pkt = build_dns_response(info, mdnspp::dns_type::any, mdnspp::service_options{});

            THEN("the packet is non-empty (other records are present)")
            {
                REQUIRE_FALSE(pkt.empty());
            }

            check_any_without_a(pkt);
        }
    }
}

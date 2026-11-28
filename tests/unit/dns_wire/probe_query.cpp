#include "helpers.h"

using mdnspp::detail::skip_dns_name;
using mdnspp::detail::build_probe_query;
using mdnspp::detail::read_u16_be;

static void check_probe_header(const std::vector<std::byte> &pkt)
{
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
}

static void check_probe_questions(const std::vector<std::byte> &pkt)
{
    THEN("both questions have QTYPE=ANY and QCLASS=0x8001 (QU bit)")
    {
        std::size_t offset = 12;
        auto span = std::span<const std::byte>(pkt);
        for(uint32_t q = 0; q < 2; ++q)
        {
            skip_dns_name(span, offset);
            uint16_t qtype = read_u16_be(pkt.data() + offset);
            uint16_t qclass = read_u16_be(pkt.data() + offset + 2);
            REQUIRE(qtype == mdnspp::detail::to_underlying(mdnspp::dns_type::any));
            REQUIRE(qclass == 0x8001);
            offset += 4;
        }
    }
}

static void check_probe_authority(const std::vector<std::byte> &pkt)
{
    THEN("the authority section contains SRV, TXT, A and AAAA records")
    {
        auto rrs = collect_rr_type_class(pkt);
        REQUIRE(rrs.size() == 4);
        REQUIRE(rrs[0].first == mdnspp::detail::to_underlying(mdnspp::dns_type::srv));
        REQUIRE(rrs[1].first == mdnspp::detail::to_underlying(mdnspp::dns_type::txt));
        REQUIRE(rrs[2].first == mdnspp::detail::to_underlying(mdnspp::dns_type::a));
        REQUIRE(rrs[3].first == mdnspp::detail::to_underlying(mdnspp::dns_type::aaaa));
    }
}

static void check_probe_question_names(const std::vector<std::byte> &pkt)
{
    THEN("the first question name matches the service_name and the second the hostname")
    {
        auto span = std::span<const std::byte>(pkt);
        auto first = mdnspp::detail::read_dns_name(span, 12);
        REQUIRE(first.has_value());
        REQUIRE(*first == "MyService._http._tcp.local.");

        std::size_t offset = 12;
        skip_dns_name(span, offset);
        offset += 4;
        auto second = mdnspp::detail::read_dns_name(span, offset);
        REQUIRE(second.has_value());
        REQUIRE(*second == "myhost.local.");
    }
}

SCENARIO("build_probe_query probes all proposed names with the full record set in authority", "[build_probe_query]")
{
    GIVEN("a test service_info with IPv4 and IPv6 addresses")
    {
        auto info = make_test_service_v46();

        WHEN("build_probe_query is called")
        {
            auto pkt = build_probe_query(info);
            check_probe_header(pkt);
            check_probe_questions(pkt);
            check_probe_authority(pkt);
            check_probe_question_names(pkt);
        }
    }
}

SCENARIO("build_probe_query writes the response mode into both questions", "[build_probe_query]")
{
    GIVEN("a test service_info")
    {
        auto info = make_test_service_v46();

        WHEN("build_probe_query is called for multicast responses")
        {
            auto pkt = build_probe_query(info, 120, mdnspp::response_mode::multicast);

            THEN("both questions have QCLASS=0x0001 (no QU bit)")
            {
                std::size_t offset = 12;
                auto span = std::span<const std::byte>(pkt);
                for(uint32_t q = 0; q < 2; ++q)
                {
                    skip_dns_name(span, offset);
                    REQUIRE(read_u16_be(pkt.data() + offset + 2) == 0x0001);
                    offset += 4;
                }
            }
        }
    }
}

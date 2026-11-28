#include "helpers.h"

using mdnspp::detail::build_dns_response;
using mdnspp::detail::skip_dns_name;
using mdnspp::detail::read_u16_be;

// walk_dns_frame strips the cache-flush bit, so these cases read the raw rrclass from the wire bytes.
static uint16_t find_first_rr_rrclass(const std::vector<std::byte> &pkt)
{
    std::size_t offset = 12;
    auto span = std::span<const std::byte>(pkt);
    skip_question_section(span, offset);
    skip_dns_name(span, offset);
    return read_u16_be(pkt.data() + offset + 2);
}

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
                    if(rtype == mdnspp::detail::to_underlying(mdnspp::dns_type::ptr))
                        REQUIRE(rclass == 0x0001);
                    else
                        REQUIRE(rclass == 0x8001);
                }
            }
        }
    }
}

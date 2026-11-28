#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>

namespace {

template <typename Fn>
void for_each_record_type(const std::vector<std::byte> &pkt, Fn &&on_type)
{
    auto cdata = std::span<const std::byte>(pkt.data(), pkt.size());
    std::size_t offset = 12;
    uint16_t qdcount = read_u16_be(pkt, 4);
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        if(!skip_dns_name(cdata, offset)) break;
        offset += 4;
    }
    uint32_t rr_total = static_cast<uint32_t>(read_u16_be(pkt, 6)) + read_u16_be(pkt, 8) + read_u16_be(pkt, 10);
    for(uint32_t rr = 0; rr < rr_total; ++rr)
    {
        if(!skip_dns_name(cdata, offset) || offset + 10 > pkt.size())
            break;
        on_type(read_u16_be(pkt, offset));
        uint16_t rdlen = read_u16_be(pkt, offset + 8); // after type, class and ttl
        offset += 10 + rdlen;
    }
}

void check_nsec_in_additional(const std::vector<sent_packet> &sent)
{
    REQUIRE_FALSE(sent.empty());
    const auto &pkt = sent.back().data;
    REQUIRE(pkt.size() >= 12);
    uint16_t arcount = read_u16_be(pkt, 10);
    REQUIRE(arcount == 1);
    bool found_nsec = false;
    for_each_record_type(pkt, [&](uint16_t rtype)
    {
        if(rtype == mdnspp::detail::to_underlying(dns_type::nsec))
            found_nsec = true;
    });
    REQUIRE(found_nsec);
}

}

SCENARIO("NSEC in Additional for unmatched type", "[nsec]")
{
    GIVEN("a live service server with IPv4 only (no IPv6)")
    {
        auto info = make_test_service();
        info.address_ipv6 = std::nullopt;
        server_fixture f{std::move(info)};
        f.go_live();
        f.clear_sent();

        WHEN("an AAAA query for our hostname is injected")
        {
            f.inject(endpoint{"192.168.1.50", 5353}, build_dns_query("myhost.local.", dns_type::aaaa,
                                                                     response_mode::multicast));
            f.server.delay_timer().fire();

            THEN("the response contains an NSEC record in Additional")
            {
                check_nsec_in_additional(f.sent());
            }
        }
    }
}

SCENARIO("No NSEC in announcements", "[nsec][announce]")
{
    GIVEN("a service server that is advancing through announcing")
    {
        server_fixture f{make_test_service()};
        f.go_live();

        THEN("none of the announcement packets contain NSEC records")
        {
            for(const auto &sp : f.sent())
            {
                if(sp.data.size() < 12) continue;
                for_each_record_type(sp.data, [](uint16_t rtype)
                {
                    REQUIRE(rtype != mdnspp::detail::to_underlying(dns_type::nsec));
                });
            }
        }
    }
}

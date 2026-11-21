#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

std::vector<std::byte> ptr_query_with_id()
{
    auto query = make_ptr_query("_http._tcp.local.");
    query[0] = std::byte{0xBE};
    query[1] = std::byte{0xEF};
    return query;
}

const sent_packet *last_sent_to(const std::vector<sent_packet> &packets, const endpoint &dest)
{
    const sent_packet *found = nullptr;
    for(const auto &pkt : packets)
    {
        if(pkt.dest == dest)
            found = &pkt;
    }
    return found;
}

void check_repeated_question(const std::vector<std::byte> &pkt)
{
    REQUIRE(read_u16_be(pkt, 4) == 1);

    auto span = std::span<const std::byte>(pkt);
    auto qname = mdnspp::detail::read_dns_name(span, 12);
    REQUIRE(qname.has_value());
    REQUIRE(dns_name{*qname} == dns_name{"_http._tcp.local."});

    std::size_t offset = 12;
    REQUIRE(skip_dns_name(span, offset));
    REQUIRE(read_u16_be(pkt, offset) == mdnspp::detail::to_underlying(dns_type::ptr));
}

std::size_t skip_questions(const std::vector<std::byte> &pkt)
{
    auto span = std::span<const std::byte>(pkt);
    std::size_t offset = 12;
    uint16_t qdcount = read_u16_be(pkt, 4);
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        REQUIRE(skip_dns_name(span, offset));
        offset += 4;
    }
    return offset;
}

void check_no_cache_flush(const std::vector<std::byte> &pkt)
{
    auto span = std::span<const std::byte>(pkt);
    std::size_t offset = skip_questions(pkt);
    uint16_t ancount = read_u16_be(pkt, 6);
    uint16_t arcount = read_u16_be(pkt, 10);
    uint32_t total = static_cast<uint32_t>(ancount) + arcount;
    REQUIRE(total >= 1);
    for(uint32_t i = 0; i < total; ++i)
    {
        REQUIRE(skip_dns_name(span, offset));
        uint16_t rclass = read_u16_be(pkt, offset + 2);
        REQUIRE((rclass & 0x8000) == 0);
        uint16_t rdlen = read_u16_be(pkt, offset + 8);
        offset += 10 + rdlen;
    }
}

void repeated_query_sections(const std::vector<std::byte> &pkt)
{
    THEN("the response repeats the query ID")
    {
        REQUIRE(read_u16_be(pkt, 0) == 0xBEEF);
    }

    THEN("the response repeats the question (qdcount=1, same qname/qtype)")
    {
        check_repeated_question(pkt);
    }

    THEN("no record carries the cache-flush bit")
    {
        check_no_cache_flush(pkt);
    }
}

}

SCENARIO("Legacy unicast response repeats query ID and question without cache-flush",
         "[service_server][legacy_unicast][rfc6762-6.7]")
{
    GIVEN("a live server")
    {
        server_fixture f;
        f.go_live();
        f.clear_sent();

        endpoint legacy_sender{"10.0.0.1", 12345};
        f.inject(legacy_sender, ptr_query_with_id());

        WHEN("the legacy unicast response is sent")
        {
            const sent_packet *response = last_sent_to(f.sent(), legacy_sender);
            REQUIRE(response != nullptr);
            const auto &pkt = response->data;
            REQUIRE(pkt.size() >= 12);
            repeated_query_sections(pkt);
        }
    }
}

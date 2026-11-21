#include "helpers.h"

#include "mdnspp/detail/server_question_section.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cstddef>

TEST_CASE("rebuild_question_section re-encodes questions for legacy unicast", "[server_query_match]")
{
    auto pkt = build_multi_query_packet({
        {"_http._tcp.local.", dns_type::ptr},
        {"myhost.local.", dns_type::a}
    });

    auto [section, count] = rebuild_question_section(std::span(pkt));
    REQUIRE(count == 2);

    auto span = std::span<const std::byte>(section);
    std::size_t offset = 0;

    auto name1 = read_dns_name(span, offset);
    REQUIRE(name1.has_value());
    CHECK(*name1 == "_http._tcp.local.");
    REQUIRE(skip_dns_name(span, offset));
    CHECK(read_u16_be(section.data() + offset) == to_underlying(dns_type::ptr));
    CHECK(read_u16_be(section.data() + offset + 2) == 0x0001);
    offset += 4;

    auto name2 = read_dns_name(span, offset);
    REQUIRE(name2.has_value());
    CHECK(*name2 == "myhost.local.");
}

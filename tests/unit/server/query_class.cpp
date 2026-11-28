#include "query_helpers.h"

#include "mdnspp/detail/server_query_match.h"

#include <catch2/generators/catch_generators.hpp>
#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cstdint>
#include <string_view>

namespace {

constexpr uint16_t qu_bit = 0x8000;

query_match_result match_class_question(std::string_view name, uint16_t qclass)
{
    auto info = make_test_info();
    info.subtypes = {"_printer"};
    auto packet = make_question_packet(0x0000, name, dns_type::ptr, qclass);
    return match_queries(std::span(packet), info, service_options{});
}

bool matched(const query_match_result &result)
{
    return result.any_matched || result.meta_matched || !result.matched_subtype.empty();
}

}

TEST_CASE("questions of class IN or ANY match owned, meta and subtype names", "[server_query_match][qclass]")
{
    auto name = GENERATE(as<std::string_view>{}, "_http._tcp.local.", "_services._dns-sd._udp.local.",
                         "_printer._sub._http._tcp.local.");
    auto qclass = GENERATE(uint16_t{1}, uint16_t{255});
    auto qu = GENERATE(uint16_t{0}, qu_bit);

    auto result = match_class_question(name, static_cast<uint16_t>(qclass | qu));

    CHECK(matched(result));
    CHECK(result.mode == (qu != 0 ? response_mode::unicast : response_mode::multicast));
}

TEST_CASE("questions of class CH or HS match nothing and leave the response mode", "[server_query_match][qclass]")
{
    auto name = GENERATE(as<std::string_view>{}, "_http._tcp.local.", "_services._dns-sd._udp.local.",
                         "_printer._sub._http._tcp.local.");
    auto qclass = GENERATE(uint16_t{3}, uint16_t{4});
    auto qu = GENERATE(uint16_t{0}, qu_bit);

    auto result = match_class_question(name, static_cast<uint16_t>(qclass | qu));

    CHECK_FALSE(matched(result));
    CHECK(result.matched.empty());
    CHECK(result.mode == response_mode::unicast);
}

TEST_CASE("a question of class CH does not turn a unicast query into a multicast one", "[server_query_match][qclass]")
{
    auto info = make_test_info();
    auto in_qu = make_question_packet(0x0000, "_http._tcp.local.", dns_type::ptr, 0x8001);
    auto chaos = make_question_packet(0x0000, "_http._tcp.local.", dns_type::ptr, 0x0003);
    in_qu[5] = std::byte{2};
    in_qu.insert(in_qu.end(), chaos.begin() + 12, chaos.end());

    auto result = match_queries(std::span(in_qu), info, service_options{});

    REQUIRE(result.matched.size() == 1);
    CHECK(result.mode == response_mode::unicast);
}

SCENARIO_METHOD(live_server, "service_server ignores a PTR question of class CH", "[service_server][qclass]")
{
    inject(endpoint{"192.168.1.50", 5353}, make_question_packet(0x0000, "_http._tcp.local.", dns_type::ptr, 3));

    CHECK_FALSE(server.delay_timer().has_pending());
    server.delay_timer().fire();
    CHECK(sent().empty());
}

SCENARIO_METHOD(live_server, "service_server answers a PTR question of class ANY", "[service_server][qclass]")
{
    inject(endpoint{"192.168.1.50", 5353}, make_question_packet(0x0000, "_http._tcp.local.", dns_type::ptr, 255));

    REQUIRE(server.delay_timer().has_pending());
    server.delay_timer().fire();
    CHECK(count_multicast_responses_after(sent(), 0) == 1);
    CHECK(response_has<record_ptr>(last_data(), "MyService"));
}

SCENARIO_METHOD(live_server, "service_server does not reply to a response that asks for its own name",
                "[service_server][qclass]")
{
    inject(endpoint{"192.168.1.50", 5353},
           make_question_packet(0x8400, "MyService._http._tcp.local.", dns_type::srv, 1));

    CHECK_FALSE(server.delay_timer().has_pending());
    server.delay_timer().fire();
    CHECK(sent().empty());
}

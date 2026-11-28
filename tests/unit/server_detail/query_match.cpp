#include "helpers.h"

#include "mdnspp/service_options.h"

#include "mdnspp/detail/server_query_match.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string_view>

namespace {

bool name_matches(std::string_view name, const service_info &info)
{
    auto encoded = wire_name(name);
    return query_name_matches(std::span(encoded), 0, info);
}

void check_single_question(const service_info &info, const service_options &opts)
{
    SECTION("single matching PTR question")
    {
        auto result = match_one("_http._tcp.local.", dns_type::ptr, info, opts);
        CHECK(result.any_matched);
        CHECK(result.accumulated_qtype == dns_type::ptr);
        CHECK(result.mode == response_mode::multicast);
        CHECK_FALSE(result.meta_matched);
        REQUIRE(result.matched.size() == 1);
        check_pair(result.matched[0], owned_name::service_type, dns_type::ptr);
    }

    SECTION("QU bit sets unicast mode")
    {
        auto result = match_one("_http._tcp.local.", dns_type::ptr, info, opts, true);
        CHECK(result.any_matched);
        CHECK(result.mode == response_mode::unicast);
    }
}

void check_enumeration_questions(const service_info &info, const service_options &opts)
{
    SECTION("meta-query is detected")
    {
        auto result = match_one("_services._dns-sd._udp.local.", dns_type::ptr, info, opts);
        CHECK(result.meta_matched);
        CHECK_FALSE(result.any_matched);
    }

    SECTION("subtype query is detected")
    {
        auto result = match_one("_printer._sub._http._tcp.local.", dns_type::ptr, info, opts);
        CHECK(result.matched_subtype == "_printer");
        CHECK_FALSE(result.any_matched);
    }
}

void check_question_pairing(const service_info &info, const service_options &opts)
{
    SECTION("two questions keep distinct name<->qtype pairs (RFC 6762 section 6)")
    {
        auto pkt = build_multi_query_packet({{"_http._tcp.local.", dns_type::ptr},
                                             {"MyApp._http._tcp.local.", dns_type::srv}});
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.any_matched);
        CHECK(result.accumulated_qtype == dns_type::any);
        REQUIRE(result.matched.size() == 2);
        check_pair(result.matched[0], owned_name::service_type, dns_type::ptr);
        check_pair(result.matched[1], owned_name::service_name, dns_type::srv);
    }

    SECTION("SRV question at the service type does NOT pair with the instance SRV")
    {
        auto result = match_one("_http._tcp.local.", dns_type::srv, info, opts);
        REQUIRE(result.matched.size() == 1);
        check_pair(result.matched[0], owned_name::service_type, dns_type::srv);
    }
}

void check_hostname_and_header_fields(const service_info &info, const service_options &opts)
{
    SECTION("hostname question is paired with the hostname")
    {
        auto result = match_one("myhost.local.", dns_type::a, info, opts);
        REQUIRE(result.matched.size() == 1);
        check_pair(result.matched[0], owned_name::hostname, dns_type::a);
    }

    SECTION("offset_after_questions points past last question")
    {
        auto pkt = build_query_packet("_http._tcp.local.", dns_type::ptr);
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.offset_after_questions == pkt.size());
    }

    SECTION("query_id captures the message ID")
    {
        auto pkt = build_query_packet("_http._tcp.local.", dns_type::ptr);
        pkt[0] = std::byte{0xAB};
        pkt[1] = std::byte{0xCD};
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.query_id == 0xABCD);
    }
}

}

TEST_CASE("query_name_matches", "[server_query_match]")
{
    auto info = make_subtype_test_info();

    SECTION("returns true for service_type match")
    {
        CHECK(name_matches("_http._tcp.local.", info));
    }

    SECTION("returns true for service_name match")
    {
        CHECK(name_matches("MyApp._http._tcp.local.", info));
    }

    SECTION("returns true for hostname match")
    {
        CHECK(name_matches("myhost.local.", info));
    }

    SECTION("returns false for non-matching name")
    {
        CHECK_FALSE(name_matches("other._http._tcp.local.", info));
    }
}

TEST_CASE("matches_meta_query", "[server_query_match]")
{
    SECTION("returns true for _services._dns-sd._udp.local.")
    {
        auto encoded = wire_name("_services._dns-sd._udp.local.");
        CHECK(matches_meta_query(std::span(encoded), 0));
    }

    SECTION("returns false for other names")
    {
        auto encoded = wire_name("_http._tcp.local.");
        CHECK_FALSE(matches_meta_query(std::span(encoded), 0));
    }
}

TEST_CASE("matches_subtype_query", "[server_query_match]")
{
    auto info = make_subtype_test_info();

    SECTION("returns subtype label when subtype matches")
    {
        auto encoded = wire_name("_printer._sub._http._tcp.local.");
        CHECK(matches_subtype_query(std::span(encoded), 0, info) == "_printer");
    }

    SECTION("returns empty for non-matching subtype")
    {
        auto encoded = wire_name("_scanner._sub._http._tcp.local.");
        CHECK(matches_subtype_query(std::span(encoded), 0, info).empty());
    }
}

TEST_CASE("has_record_type", "[server_query_match]")
{
    auto info = make_subtype_test_info();

    CHECK(has_record_type(dns_type::ptr, info));
    CHECK(has_record_type(dns_type::srv, info));
    CHECK(has_record_type(dns_type::txt, info));
    CHECK(has_record_type(dns_type::any, info));
    CHECK(has_record_type(dns_type::a, info));          // has ipv4
    CHECK_FALSE(has_record_type(dns_type::aaaa, info)); // no ipv6
    CHECK_FALSE(has_record_type(dns_type::nsec, info)); // unknown type
}

TEST_CASE("match_queries preserves per-question name<->qtype pairing", "[server_query_match]")
{
    auto info = make_subtype_test_info();
    service_options opts;
    opts.respond_to_meta_queries = true;

    check_single_question(info, opts);
    check_enumeration_questions(info, opts);
    check_question_pairing(info, opts);
    check_hostname_and_header_fields(info, opts);
}

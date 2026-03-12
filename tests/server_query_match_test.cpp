// tests/server_query_match_test.cpp
// Unit tests for detail::query_name_matches, matches_meta_query,
// matches_subtype_query, has_record_type, match_queries.

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_query_match.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <string>
#include <cstddef>
#include <cstdint>
#include <optional>

using namespace mdnspp;
using namespace mdnspp::detail;

static service_info make_test_info()
{
    service_info info;
    info.service_name = "MyApp._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "myhost.local.";
    info.port = 8080;
    info.priority = 0;
    info.weight = 0;
    info.address_ipv4 = "192.168.1.10";
    info.address_ipv6 = std::nullopt;
    info.txt_records = {};
    info.subtypes = {"_printer"};
    return info;
}

// Helper: build wire-encoded DNS name bytes
static std::vector<std::byte> wire_name(std::string_view name)
{
    return encode_dns_name(name);
}

// Helper: build a minimal DNS query packet with one question
static std::vector<std::byte> build_query_packet(std::string_view qname, dns_type qtype,
                                                 bool qu_bit = false)
{
    std::vector<std::byte> pkt;
    // Header: 12 bytes
    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x0000); // flags (query)
    push_u16_be(pkt, 0x0001); // qdcount = 1
    push_u16_be(pkt, 0x0000); // ancount
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    auto encoded = encode_dns_name(qname);
    pkt.insert(pkt.end(), encoded.begin(), encoded.end());
    push_u16_be(pkt, std::to_underlying(qtype));
    uint16_t qclass = 0x0001; // IN
    if(qu_bit)
        qclass |= 0x8000;
    push_u16_be(pkt, qclass);

    return pkt;
}

// Helper: build query packet with multiple questions
static std::vector<std::byte> build_multi_query_packet(
    std::initializer_list<std::pair<std::string_view, dns_type>> questions,
    bool qu_bit = false)
{
    std::vector<std::byte> pkt;
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, static_cast<uint16_t>(questions.size()));
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);
    push_u16_be(pkt, 0x0000);

    for(auto &[name, qtype] : questions)
    {
        auto encoded = encode_dns_name(name);
        pkt.insert(pkt.end(), encoded.begin(), encoded.end());
        push_u16_be(pkt, std::to_underlying(qtype));
        uint16_t qclass = 0x0001;
        if(qu_bit)
            qclass |= 0x8000;
        push_u16_be(pkt, qclass);
    }

    return pkt;
}

TEST_CASE("query_name_matches", "[server_query_match]")
{
    auto info = make_test_info();

    SECTION("returns true for service_type match")
    {
        auto encoded = wire_name("_http._tcp.local.");
        // Name occupies [0..encoded.size())
        CHECK(query_name_matches(std::span(encoded), 0, info));
    }

    SECTION("returns true for service_name match")
    {
        auto encoded = wire_name("MyApp._http._tcp.local.");
        CHECK(query_name_matches(std::span(encoded), 0, info));
    }

    SECTION("returns true for hostname match")
    {
        auto encoded = wire_name("myhost.local.");
        CHECK(query_name_matches(std::span(encoded), 0, info));
    }

    SECTION("returns false for non-matching name")
    {
        auto encoded = wire_name("other._http._tcp.local.");
        CHECK_FALSE(query_name_matches(std::span(encoded), 0, info));
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
    auto info = make_test_info();

    SECTION("returns subtype label when subtype matches")
    {
        auto encoded = wire_name("_printer._sub._http._tcp.local.");
        auto result = matches_subtype_query(std::span(encoded), 0, info);
        CHECK(result == "_printer");
    }

    SECTION("returns empty for non-matching subtype")
    {
        auto encoded = wire_name("_scanner._sub._http._tcp.local.");
        auto result = matches_subtype_query(std::span(encoded), 0, info);
        CHECK(result.empty());
    }
}

TEST_CASE("has_record_type", "[server_query_match]")
{
    auto info = make_test_info();

    CHECK(has_record_type(dns_type::ptr, info));
    CHECK(has_record_type(dns_type::srv, info));
    CHECK(has_record_type(dns_type::txt, info));
    CHECK(has_record_type(dns_type::any, info));
    CHECK(has_record_type(dns_type::a, info));       // has ipv4
    CHECK_FALSE(has_record_type(dns_type::aaaa, info)); // no ipv6
    CHECK_FALSE(has_record_type(dns_type::nsec, info)); // unknown type
}

TEST_CASE("match_queries accumulates multiple questions", "[server_query_match]")
{
    auto info = make_test_info();
    service_options opts;
    opts.respond_to_meta_queries = true;

    SECTION("single matching PTR question")
    {
        auto pkt = build_query_packet("_http._tcp.local.", dns_type::ptr);
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.any_matched);
        CHECK(result.accumulated_qtype == dns_type::ptr);
        CHECK(result.mode == response_mode::multicast);
        CHECK_FALSE(result.needs_nsec);
        CHECK_FALSE(result.meta_matched);
    }

    SECTION("QU bit sets unicast mode")
    {
        auto pkt = build_query_packet("_http._tcp.local.", dns_type::ptr, true);
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.any_matched);
        CHECK(result.mode == response_mode::unicast);
    }

    SECTION("meta-query is detected")
    {
        auto pkt = build_query_packet("_services._dns-sd._udp.local.", dns_type::ptr);
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.meta_matched);
        CHECK_FALSE(result.any_matched);
    }

    SECTION("subtype query is detected")
    {
        auto pkt = build_query_packet("_printer._sub._http._tcp.local.", dns_type::ptr);
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.matched_subtype == "_printer");
        CHECK_FALSE(result.any_matched);
    }

    SECTION("mixed questions accumulate types to ANY")
    {
        auto pkt = build_multi_query_packet({
            {"_http._tcp.local.", dns_type::ptr},
            {"MyApp._http._tcp.local.", dns_type::srv}
        });
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.any_matched);
        CHECK(result.accumulated_qtype == dns_type::any);
    }

    SECTION("offset_after_questions points past last question")
    {
        auto pkt = build_query_packet("_http._tcp.local.", dns_type::ptr);
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.offset_after_questions == pkt.size());
    }

    SECTION("needs_nsec set for unmatched record type")
    {
        // Query for AAAA but info has no ipv6
        auto pkt = build_query_packet("myhost.local.", dns_type::aaaa);
        auto result = match_queries(std::span(pkt), info, opts);
        CHECK(result.any_matched);
        CHECK(result.needs_nsec);
    }
}

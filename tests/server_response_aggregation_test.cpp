// tests/server_response_aggregation_test.cpp
// Unit tests for detail::pending_response and build_response_with_nsec,
// build_meta_query_response, build_subtype_response.

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/server_response_aggregation.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
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
    info.address_ipv4 = "192.168.1.10";
    info.address_ipv6 = std::nullopt;
    info.txt_records = {};
    info.subtypes = {"_printer"};
    return info;
}

TEST_CASE("pending_response starts unarmed", "[server_response_aggregation]")
{
    pending_response pr;
    CHECK_FALSE(pr.armed);
    CHECK(pr.qtype == dns_type::none);
    CHECK_FALSE(pr.needs_nsec);
}

TEST_CASE("pending_response merge", "[server_response_aggregation]")
{
    SECTION("first merge arms with given values")
    {
        pending_response pr;
        suppression_mask mask{.ptr = true};
        pr.merge(dns_type::ptr, false, mask);

        CHECK(pr.armed);
        CHECK(pr.qtype == dns_type::ptr);
        CHECK_FALSE(pr.needs_nsec);
        CHECK(pr.suppression.ptr);
    }

    SECTION("merge with different qtype escalates to any")
    {
        pending_response pr;
        pr.merge(dns_type::ptr, false, {});
        pr.merge(dns_type::srv, false, {});
        CHECK(pr.qtype == dns_type::any);
    }

    SECTION("merge ANDs suppression masks")
    {
        pending_response pr;
        suppression_mask m1{.ptr = true, .srv = true, .a = false};
        suppression_mask m2{.ptr = true, .srv = false, .a = false};
        pr.merge(dns_type::ptr, false, m1);
        pr.merge(dns_type::ptr, false, m2);

        CHECK(pr.suppression.ptr);
        CHECK_FALSE(pr.suppression.srv);
        CHECK_FALSE(pr.suppression.a);
    }

    SECTION("merge ORs needs_nsec")
    {
        pending_response pr;
        pr.merge(dns_type::ptr, false, {});
        pr.merge(dns_type::srv, true, {});
        CHECK(pr.needs_nsec);
    }
}

TEST_CASE("pending_response reset clears all fields", "[server_response_aggregation]")
{
    pending_response pr;
    pr.merge(dns_type::ptr, true, {.ptr = true});
    pr.reset();

    CHECK_FALSE(pr.armed);
    CHECK(pr.qtype == dns_type::none);
    CHECK_FALSE(pr.needs_nsec);
    CHECK_FALSE(pr.suppression.ptr);
}

TEST_CASE("build_response_with_nsec", "[server_response_aggregation]")
{
    auto info = make_test_info();

    SECTION("produces valid packet for PTR query")
    {
        suppression_mask mask;
        auto response = build_response_with_nsec(info, dns_type::ptr, false, mask, false);
        REQUIRE(response.size() >= 12);
        uint16_t flags = read_u16_be(response.data() + 2);
        CHECK(flags == 0x8400);
    }

    SECTION("returns empty when type is fully suppressed")
    {
        suppression_mask mask{.ptr = true};
        auto response = build_response_with_nsec(info, dns_type::ptr, false, mask, true);
        CHECK(response.empty());
    }

    SECTION("appends NSEC record when needs_nsec=true")
    {
        suppression_mask mask;
        auto without_nsec = build_response_with_nsec(info, dns_type::ptr, false, mask, false);
        auto with_nsec = build_response_with_nsec(info, dns_type::ptr, true, mask, false);
        CHECK(with_nsec.size() > without_nsec.size());
        // Check arcount was incremented
        uint16_t arcount = read_u16_be(with_nsec.data() + 10);
        uint16_t arcount_orig = read_u16_be(without_nsec.data() + 10);
        CHECK(arcount == arcount_orig + 1);
    }

    SECTION("does not suppress when suppress_enabled=false")
    {
        suppression_mask mask{.ptr = true};
        auto response = build_response_with_nsec(info, dns_type::ptr, false, mask, false);
        CHECK_FALSE(response.empty());
    }
}

TEST_CASE("build_meta_query_response", "[server_response_aggregation]")
{
    auto info = make_test_info();
    auto response = build_meta_query_response(info);

    REQUIRE(response.size() >= 12);
    uint16_t flags = read_u16_be(response.data() + 2);
    CHECK(flags == 0x8400);
    uint16_t ancount = read_u16_be(response.data() + 6);
    CHECK(ancount == 1);
}

TEST_CASE("build_subtype_response", "[server_response_aggregation]")
{
    auto info = make_test_info();
    auto response = build_subtype_response("_printer", info);

    REQUIRE(response.size() >= 12);
    uint16_t flags = read_u16_be(response.data() + 2);
    CHECK(flags == 0x8400);
    uint16_t ancount = read_u16_be(response.data() + 6);
    CHECK(ancount == 1);
}

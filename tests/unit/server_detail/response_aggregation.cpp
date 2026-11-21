#include "helpers.h"
#include "response_helpers.h"

#include "mdnspp/service_options.h"

#include "mdnspp/detail/byte_order.h"
#include "mdnspp/detail/server_answer_plan.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/server_response_aggregation.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>

TEST_CASE("pending_response merges plans", "[server_response_aggregation]")
{
    pending_response pr;
    CHECK_FALSE(pr.armed);

    answer_plan p1;
    p1.ptr = true;
    pr.merge(p1);
    CHECK(pr.armed);
    CHECK(pr.plan.ptr);

    answer_plan p2;
    p2.srv = true;
    p2.nsec_hostname = true;
    pr.merge(p2);
    CHECK(pr.plan.ptr);
    CHECK(pr.plan.srv);
    CHECK(pr.plan.nsec_hostname);

    pr.reset();
    CHECK_FALSE(pr.armed);
    CHECK(pr.plan.empty());
}

TEST_CASE("apply_suppression clears suppressed record types but never NSEC", "[server_response_aggregation]")
{
    answer_plan plan;
    plan.ptr = true;
    plan.srv = true;
    plan.nsec_hostname = true;

    suppression_mask mask{.ptr = true};
    apply_suppression(plan, mask);

    CHECK_FALSE(plan.ptr);
    CHECK(plan.srv);
    CHECK(plan.nsec_hostname);
}

TEST_CASE("min_planned_ttl and qu_requires_multicast", "[server_response_aggregation][qu]")
{
    service_options opts;
    opts.ptr_ttl = std::chrono::seconds{4500};
    opts.srv_ttl = std::chrono::seconds{120};

    answer_plan plan;
    plan.ptr = true;
    plan.srv = true;
    CHECK(min_planned_ttl(plan, opts) == std::chrono::seconds{120});

    using tp = std::chrono::steady_clock::time_point;
    tp epoch{};

    // Multicast 10 s ago with a 120 s TTL: within the last quarter (30 s) -> unicast OK.
    CHECK_FALSE(qu_requires_multicast(epoch, epoch + std::chrono::seconds{10}, std::chrono::seconds{120}));

    // Multicast 31 s ago: outside the quarter -> must multicast (RFC 6762 section 5.4).
    CHECK(qu_requires_multicast(epoch, epoch + std::chrono::seconds{31}, std::chrono::seconds{120}));
}

TEST_CASE("build_meta_query_response", "[server_response_aggregation]")
{
    auto info = make_subtype_test_info();
    auto response = build_meta_query_response(info);

    REQUIRE(response.size() >= 12);
    uint16_t flags = read_u16_be(response.data() + 2);
    CHECK(flags == 0x8400);
    uint16_t ancount = read_u16_be(response.data() + 6);
    CHECK(ancount == 1);
}

TEST_CASE("build_subtype_response", "[server_response_aggregation]")
{
    auto info = make_subtype_test_info();
    auto response = build_subtype_response("_printer", info);

    REQUIRE(response.size() >= 12);
    uint16_t flags = read_u16_be(response.data() + 2);
    CHECK(flags == 0x8400);
    uint16_t ancount = read_u16_be(response.data() + 6);
    CHECK(ancount == 1);
}

TEST_CASE("build_meta_query_response uses custom TTL", "[server_response_aggregation]")
{
    auto info = make_subtype_test_info();
    auto response = build_meta_query_response(info, 600);

    auto rrs = collect_rrs(response);
    REQUIRE(rrs.size() == 1);
    CHECK(rrs[0].ttl == 600);
}

TEST_CASE("build_subtype_response uses custom TTL", "[server_response_aggregation]")
{
    auto info = make_subtype_test_info();
    auto response = build_subtype_response("_printer", info, 900);

    auto rrs = collect_rrs(response);
    REQUIRE(rrs.size() == 1);
    CHECK(rrs[0].ttl == 900);
}

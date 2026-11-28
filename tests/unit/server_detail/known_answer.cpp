#include "helpers.h"

#include "mdnspp/service_options.h"

#include "mdnspp/detail/server_known_answer.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <string_view>
#include <initializer_list>

namespace {

suppression_mask parse_answers(std::initializer_list<answer_spec> answers, const service_info &info,
                               const ka_thresholds &th = {})
{
    std::size_t offset;
    auto pkt = build_answer_packet(answers, offset);
    return parse_known_answers(std::span(pkt), offset, info, th);
}

answer_spec ptr_answer(std::string_view owner, uint32_t ttl, std::string_view target)
{
    return {owner, dns_type::ptr, ttl, wire_name(target)};
}

void check_matching_ptr_answers(const service_info &info)
{
    SECTION("returns empty mask for no answers")
    {
        auto mask = parse_answers({}, info);
        CHECK_FALSE(mask.ptr);
        CHECK_FALSE(mask.srv);
        CHECK_FALSE(mask.a);
        CHECK_FALSE(mask.aaaa);
        CHECK_FALSE(mask.txt);
    }

    SECTION("sets ptr=true for matching PTR answer naming our instance with TTL >= threshold")
    {
        auto mask = parse_answers({ptr_answer("_http._tcp.local.", 4500, "MyApp._http._tcp.local.")}, info);
        CHECK(mask.ptr);
        CHECK_FALSE(mask.srv);
    }

    SECTION("suppresses case-variant answers (RFC 6762 section 16: comparison is case-insensitive)")
    {
        CHECK(parse_answers({ptr_answer("_HTTP._TCP.LOCAL.", 4500, "MYAPP._HTTP._TCP.LOCAL.")}, info).ptr);
    }
}

void check_ignored_ptr_answers(const service_info &info)
{
    SECTION("does NOT suppress a PTR answer naming a DIFFERENT instance")
    {
        // RFC 6762 §7.1: a browse query's known answers list the responder's own instances. A PTR for another
        // node of the same type must not suppress ours, or a live but silent responder never answers its browse.
        CHECK_FALSE(parse_answers({ptr_answer("_http._tcp.local.", 4500, "OtherApp._http._tcp.local.")}, info).ptr);
    }

    SECTION("ignores answers with TTL < threshold")
    {
        CHECK_FALSE(parse_answers({ptr_answer("_http._tcp.local.", 1000, "MyApp._http._tcp.local.")}, info).ptr);
    }

    SECTION("ignores answers with non-matching names")
    {
        CHECK_FALSE(parse_answers({ptr_answer("_other._tcp.local.", 4500, "MyApp._http._tcp.local.")}, info).ptr);
    }
}

void check_srv_answers(const service_info &info)
{
    SECTION("sets srv=true for SRV answer with matching rdata")
    {
        auto rdata = srv_rdata(0, 0, 8080, "myhost.local.");
        CHECK(parse_answers({{"MyApp._http._tcp.local.", dns_type::srv, 4500, rdata}}, info).srv);
    }

    SECTION("does NOT suppress an SRV answer with stale rdata (different port)")
    {
        // RFC 6762 §7.1: rdata must match; a querier holding a stale SRV (old port) must still get our answer.
        auto rdata = srv_rdata(0, 0, 9999, "myhost.local.");
        CHECK_FALSE(parse_answers({{"MyApp._http._tcp.local.", dns_type::srv, 4500, rdata}}, info).srv);
    }

    SECTION("does NOT suppress an SRV answer owned by the hostname")
    {
        auto rdata = srv_rdata(0, 0, 8080, "myhost.local.");
        CHECK_FALSE(parse_answers({{"myhost.local.", dns_type::srv, 4500, rdata}}, info).srv);
    }
}

void check_address_and_txt_answers(const service_info &info)
{
    SECTION("sets a=true for A answer with matching address on hostname")
    {
        CHECK(parse_answers({{"myhost.local.", dns_type::a, 4500, a_rdata("192.168.1.10")}}, info).a);
    }

    SECTION("does NOT suppress an A answer with a different address")
    {
        CHECK_FALSE(parse_answers({{"myhost.local.", dns_type::a, 4500, a_rdata("10.0.0.99")}}, info).a);
    }

    SECTION("sets txt=true only for byte-identical TXT rdata")
    {
        auto info_txt = make_test_info();
        info_txt.txt_records = {service_txt{"path", "/api"}};
        auto matching = encode_txt_records(info_txt.txt_records);
        auto different = encode_txt_records({service_txt{"path", "/other"}});
        CHECK(parse_answers({{"MyApp._http._tcp.local.", dns_type::txt, 4500, matching}}, info_txt).txt);
        CHECK_FALSE(parse_answers({{"MyApp._http._tcp.local.", dns_type::txt, 4500, different}}, info_txt).txt);
    }
}

}

TEST_CASE("parse_known_answers", "[server_known_answer]")
{
    auto info = make_test_info();
    check_matching_ptr_answers(info);
    check_ignored_ptr_answers(info);
    check_srv_answers(info);
    check_address_and_txt_answers(info);
}

TEST_CASE("parse_known_answers with custom per-type thresholds", "[server_known_answer]")
{
    auto info = make_test_info();
    auto answer = ptr_answer("_http._tcp.local.", 500, "MyApp._http._tcp.local.");

    SECTION("suppressed when TTL >= custom threshold")
    {
        CHECK(parse_answers({answer}, info, ka_thresholds{.ptr = 400}).ptr);
    }

    SECTION("not suppressed when TTL < custom threshold")
    {
        CHECK_FALSE(parse_answers({answer}, info, ka_thresholds{.ptr = 600}).ptr);
    }
}

TEST_CASE("make_ka_thresholds derives per-type thresholds from the TTLs actually sent",
          "[server_known_answer]")
{
    service_options opts;
    opts.ptr_ttl = std::chrono::seconds{4500};
    opts.srv_ttl = std::chrono::seconds{120};
    opts.txt_ttl = std::chrono::seconds{4500};
    opts.a_ttl = std::chrono::seconds{120};
    opts.aaaa_ttl = std::chrono::seconds{120};

    auto th = make_ka_thresholds(opts, 0.5);
    CHECK(th.ptr == 2250);
    CHECK(th.srv == 60);
    CHECK(th.txt == 2250);
    CHECK(th.a == 60);
    CHECK(th.aaaa == 60);
}

TEST_CASE("suppress_from_records applies per-type thresholds and rdata matching",
          "[server_known_answer]")
{
    auto info = make_test_info();
    std::vector<mdns_record_variant> records{
        make_ptr("_http._tcp.local.", "MyApp._http._tcp.local.", 4500),
        make_srv("MyApp._http._tcp.local.", 9999, "myhost.local.", 4500), // stale rdata: must NOT suppress
        make_a("myhost.local.", "192.168.1.10", 10),                       // below threshold: must NOT suppress
    };
    auto mask = suppress_from_records(records, info, ka_thresholds{.ptr = 2250, .srv = 60, .a = 60});

    CHECK(mask.ptr);
    CHECK_FALSE(mask.srv);
    CHECK_FALSE(mask.a);
}

// tests/server_response_aggregation_test.cpp
// Unit tests for detail::answer_plan, plan_answers, pending_response,
// build_answer_response (including NSEC owner/bitmap and legacy unicast
// framing), build_meta_query_response and build_subtype_response.

#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_known_answer.h"
#include "mdnspp/detail/server_response_aggregation.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

using namespace mdnspp;
using namespace mdnspp::detail;

namespace {

struct parsed_rr
{
    std::string name;
    uint16_t rtype{};
    uint16_t rclass{};
    uint32_t ttl{};
    std::vector<std::byte> rdata;
    bool in_answer_section{};
};

// Walks all resource records of a DNS packet, skipping the question section.
std::vector<parsed_rr> collect_rrs(const std::vector<std::byte> &pkt)
{
    std::vector<parsed_rr> rrs;
    if(pkt.size() < 12)
        return rrs;

    auto span = std::span<const std::byte>(pkt);
    uint16_t qdcount = read_u16_be(pkt.data() + 4);
    uint16_t ancount = read_u16_be(pkt.data() + 6);
    uint16_t nscount = read_u16_be(pkt.data() + 8);
    uint16_t arcount = read_u16_be(pkt.data() + 10);
    uint32_t total = static_cast<uint32_t>(ancount) + nscount + arcount;

    size_t offset = 12;
    for(uint16_t i = 0; i < qdcount; ++i)
    {
        if(!skip_dns_name(span, offset))
            return rrs;
        offset += 4;
    }

    for(uint32_t i = 0; i < total; ++i)
    {
        auto name = read_dns_name(span, offset);
        if(!name.has_value() || !skip_dns_name(span, offset))
            break;
        if(offset + 10 > pkt.size())
            break;
        parsed_rr rr;
        rr.name = *name;
        rr.rtype = read_u16_be(pkt.data() + offset);
        rr.rclass = read_u16_be(pkt.data() + offset + 2);
        rr.ttl = read_u32_be(pkt.data() + offset + 4);
        uint16_t rdlen = read_u16_be(pkt.data() + offset + 8);
        offset += 10;
        if(offset + rdlen > pkt.size())
            break;
        rr.rdata.assign(pkt.data() + offset, pkt.data() + offset + rdlen);
        rr.in_answer_section = i < ancount;
        offset += rdlen;
        rrs.push_back(std::move(rr));
    }
    return rrs;
}

const parsed_rr *find_rr(const std::vector<parsed_rr> &rrs, dns_type t,
                         std::string_view name = {})
{
    for(const auto &rr : rrs)
    {
        if(rr.rtype != to_underlying(t))
            continue;
        if(!name.empty() && dns_name{rr.name} != dns_name{name})
            continue;
        return &rr;
    }
    return nullptr;
}

service_info make_test_info()
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

}

TEST_CASE("plan_answers pairs each question with its own name and qtype", "[answer_plan]")
{
    auto info = make_test_info();

    SECTION("service_type PTR plans only the PTR record")
    {
        std::vector<question_match> qs{{owned_name::service_type, dns_type::ptr}};
        auto plan = plan_answers(qs, info);
        CHECK(plan.ptr);
        CHECK_FALSE(plan.srv);
        CHECK_FALSE(plan.has_nsec());
    }

    SECTION("SRV at the service type plans an NSEC, not the instance SRV (RFC 6762 section 6.1)")
    {
        std::vector<question_match> qs{{owned_name::service_type, dns_type::srv}};
        auto plan = plan_answers(qs, info);
        CHECK_FALSE(plan.srv);
        CHECK_FALSE(plan.ptr);
        CHECK(plan.nsec_service_type);
    }

    SECTION("instance SRV plans the SRV record")
    {
        std::vector<question_match> qs{{owned_name::service_name, dns_type::srv}};
        auto plan = plan_answers(qs, info);
        CHECK(plan.srv);
        CHECK_FALSE(plan.ptr);
    }

    SECTION("instance ANY plans SRV and TXT")
    {
        std::vector<question_match> qs{{owned_name::service_name, dns_type::any}};
        auto plan = plan_answers(qs, info);
        CHECK(plan.srv);
        CHECK(plan.txt);
        CHECK_FALSE(plan.ptr);
    }

    SECTION("PTR at the instance name plans an NSEC for the instance")
    {
        std::vector<question_match> qs{{owned_name::service_name, dns_type::ptr}};
        auto plan = plan_answers(qs, info);
        CHECK_FALSE(plan.ptr);
        CHECK(plan.nsec_service_name);
    }

    SECTION("hostname A plans the A record when an address exists")
    {
        std::vector<question_match> qs{{owned_name::hostname, dns_type::a}};
        auto plan = plan_answers(qs, info);
        CHECK(plan.a);
        CHECK_FALSE(plan.has_nsec());
    }

    SECTION("hostname AAAA plans an NSEC when no IPv6 address exists")
    {
        std::vector<question_match> qs{{owned_name::hostname, dns_type::aaaa}};
        auto plan = plan_answers(qs, info);
        CHECK_FALSE(plan.aaaa);
        CHECK(plan.nsec_hostname);
    }

    SECTION("multiple questions do not degrade to a full dump")
    {
        std::vector<question_match> qs{
            {owned_name::service_type, dns_type::ptr},
            {owned_name::service_name, dns_type::srv},
        };
        auto plan = plan_answers(qs, info);
        CHECK(plan.ptr);
        CHECK(plan.srv);
        CHECK_FALSE(plan.txt);
        CHECK_FALSE(plan.a);
    }
}

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

TEST_CASE("build_answer_response", "[server_response_aggregation]")
{
    auto info = make_test_info();

    SECTION("produces valid packet for a PTR plan")
    {
        answer_plan plan;
        plan.ptr = true;
        auto response = build_answer_response(info, plan, service_options{});
        REQUIRE(response.size() >= 12);
        uint16_t flags = read_u16_be(response.data() + 2);
        CHECK(flags == 0x8400);

        auto rrs = collect_rrs(response);
        auto *ptr = find_rr(rrs, dns_type::ptr);
        REQUIRE(ptr != nullptr);
        CHECK(ptr->in_answer_section);
        // PTR pulls SRV/TXT/A additionals (RFC 6763 section 12)
        CHECK(find_rr(rrs, dns_type::srv) != nullptr);
        CHECK(find_rr(rrs, dns_type::txt) != nullptr);
        CHECK(find_rr(rrs, dns_type::a) != nullptr);
    }

    SECTION("returns empty for an empty plan")
    {
        CHECK(build_answer_response(info, answer_plan{}, service_options{}).empty());
    }

    SECTION("NSEC owner is the instance name with SRV/TXT/NSEC bitmap")
    {
        answer_plan plan;
        plan.nsec_service_name = true;
        auto response = build_answer_response(info, plan, service_options{});
        REQUIRE_FALSE(response.empty());

        auto rrs = collect_rrs(response);
        auto *nsec = find_rr(rrs, dns_type::nsec);
        REQUIRE(nsec != nullptr);
        CHECK(dns_name{nsec->name} == info.service_name);

        // rdata = owner name + window block; bitmap must flag TXT(16), SRV(33), NSEC(47)
        auto owner = encode_dns_name(info.service_name).value();
        REQUIRE(nsec->rdata.size() > owner.size() + 2);
        auto window = std::to_integer<uint8_t>(nsec->rdata[owner.size()]);
        auto length = std::to_integer<uint8_t>(nsec->rdata[owner.size() + 1]);
        CHECK(window == 0);
        REQUIRE(length == 6);
        const std::byte *bitmap = nsec->rdata.data() + owner.size() + 2;
        CHECK(std::to_integer<uint8_t>(bitmap[2]) == 0x80); // TXT(16)
        CHECK(std::to_integer<uint8_t>(bitmap[4]) == 0x40); // SRV(33)
        CHECK(std::to_integer<uint8_t>(bitmap[5]) == 0x01); // NSEC(47)
    }

    SECTION("NSEC owner is the hostname with only the existing address types")
    {
        answer_plan plan;
        plan.nsec_hostname = true;
        auto response = build_answer_response(info, plan, service_options{});
        REQUIRE_FALSE(response.empty());

        auto rrs = collect_rrs(response);
        auto *nsec = find_rr(rrs, dns_type::nsec);
        REQUIRE(nsec != nullptr);
        CHECK(dns_name{nsec->name} == info.hostname);

        auto owner = encode_dns_name(info.hostname).value();
        REQUIRE(nsec->rdata.size() > owner.size() + 2);
        auto length = std::to_integer<uint8_t>(nsec->rdata[owner.size() + 1]);
        REQUIRE(length == 1); // only A(1) exists (no IPv6 configured)
        const std::byte *bitmap = nsec->rdata.data() + owner.size() + 2;
        CHECK(std::to_integer<uint8_t>(bitmap[0]) == 0x40); // A(1)
    }

    SECTION("NSEC owner is the service type with only the PTR bit")
    {
        answer_plan plan;
        plan.nsec_service_type = true;
        auto response = build_answer_response(info, plan, service_options{});
        REQUIRE_FALSE(response.empty());

        auto rrs = collect_rrs(response);
        auto *nsec = find_rr(rrs, dns_type::nsec);
        REQUIRE(nsec != nullptr);
        CHECK(dns_name{nsec->name} == info.service_type);

        auto owner = encode_dns_name(info.service_type).value();
        auto length = std::to_integer<uint8_t>(nsec->rdata[owner.size() + 1]);
        REQUIRE(length == 2);
        const std::byte *bitmap = nsec->rdata.data() + owner.size() + 2;
        CHECK(std::to_integer<uint8_t>(bitmap[1]) == 0x08); // PTR(12)
    }

    SECTION("uses per-type TTLs from service_options")
    {
        service_options opts;
        opts.ptr_ttl    = std::chrono::seconds{1234};
        opts.srv_ttl    = std::chrono::seconds{1234};
        opts.txt_ttl    = std::chrono::seconds{1234};
        opts.a_ttl      = std::chrono::seconds{1234};
        opts.aaaa_ttl   = std::chrono::seconds{1234};
        opts.record_ttl = std::chrono::seconds{1234};

        answer_plan plan;
        plan.ptr = true;
        auto response = build_answer_response(info, plan, opts);
        auto rrs = collect_rrs(response);
        REQUIRE_FALSE(rrs.empty());
        for(const auto &rr : rrs)
            CHECK(rr.ttl == 1234);
    }
}

TEST_CASE("build_answer_response legacy unicast framing (RFC 6762 section 6.7)",
          "[server_response_aggregation][legacy]")
{
    auto info = make_test_info();

    // Simulated legacy query: one PTR question with a nonzero ID.
    std::vector<std::byte> questions;
    auto qname = encode_dns_name(info.service_type).value();
    questions.insert(questions.end(), qname.begin(), qname.end());
    push_u16_be(questions, to_underlying(dns_type::ptr));
    push_u16_be(questions, 0x0001);

    answer_plan plan;
    plan.ptr = true;

    response_header_options hdr;
    hdr.id = 0x1234;
    hdr.cache_flush = false;
    hdr.include_nsec = false;
    hdr.ttl_cap = 10;
    hdr.questions = std::span<const std::byte>(questions);
    hdr.qdcount = 1;

    auto response = build_answer_response(info, plan, service_options{}, hdr);
    REQUIRE(response.size() >= 12);

    SECTION("repeats the query ID")
    {
        CHECK(read_u16_be(response.data()) == 0x1234);
    }

    SECTION("repeats the question")
    {
        CHECK(read_u16_be(response.data() + 4) == 1);
        auto span = std::span<const std::byte>(response);
        auto name = read_dns_name(span, 12);
        REQUIRE(name.has_value());
        CHECK(dns_name{*name} == info.service_type);
    }

    SECTION("never sets the cache-flush bit and caps TTLs")
    {
        auto rrs = collect_rrs(response);
        REQUIRE_FALSE(rrs.empty());
        for(const auto &rr : rrs)
        {
            CHECK((rr.rclass & 0x8000) == 0);
            CHECK(rr.ttl <= 10);
        }
    }
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
    CHECK_FALSE(qu_requires_multicast(epoch, epoch + std::chrono::seconds{10},
                                      std::chrono::seconds{120}));

    // Multicast 31 s ago: outside the quarter -> must multicast (RFC 6762 section 5.4).
    CHECK(qu_requires_multicast(epoch, epoch + std::chrono::seconds{31},
                                std::chrono::seconds{120}));
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

TEST_CASE("build_meta_query_response uses custom TTL", "[server_response_aggregation]")
{
    auto info = make_test_info();
    auto response = build_meta_query_response(info, 600);

    auto rrs = collect_rrs(response);
    REQUIRE(rrs.size() == 1);
    CHECK(rrs[0].ttl == 600);
}

TEST_CASE("build_subtype_response uses custom TTL", "[server_response_aggregation]")
{
    auto info = make_test_info();
    auto response = build_subtype_response("_printer", info, 900);

    auto rrs = collect_rrs(response);
    REQUIRE(rrs.size() == 1);
    CHECK(rrs[0].ttl == 900);
}

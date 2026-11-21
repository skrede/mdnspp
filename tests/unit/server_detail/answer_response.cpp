#include "helpers.h"
#include "response_helpers.h"

#include "mdnspp/dns_name.h"
#include "mdnspp/service_info.h"
#include "mdnspp/service_options.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/byte_order.h"
#include "mdnspp/detail/server_answer_plan.h"
#include "mdnspp/detail/server_response_aggregation.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <chrono>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

parsed_rr planned_nsec(const service_info &info, const answer_plan &plan, const dns_name &owner)
{
    auto response = build_answer_response(info, plan, service_options{});
    REQUIRE_FALSE(response.empty());
    auto rrs = collect_rrs(response);
    auto *nsec = find_rr(rrs, dns_type::nsec);
    REQUIRE(nsec != nullptr);
    CHECK(dns_name{nsec->name} == owner);
    return *nsec;
}

uint8_t rdata_byte(const parsed_rr &rr, std::size_t index)
{
    return std::to_integer<uint8_t>(rr.rdata[index]);
}

service_options uniform_ttls(std::chrono::seconds ttl)
{
    service_options opts;
    opts.ptr_ttl = ttl;
    opts.srv_ttl = ttl;
    opts.txt_ttl = ttl;
    opts.a_ttl = ttl;
    opts.aaaa_ttl = ttl;
    opts.fallback_record_ttl = ttl;
    return opts;
}

void ptr_and_empty_plan_sections(const service_info &info)
{
    SECTION("produces valid packet for a PTR plan")
    {
        auto response = build_answer_response(info, answer_plan{.ptr = true}, service_options{});
        REQUIRE(response.size() >= 12);
        CHECK(read_u16_be(response.data() + 2) == 0x8400);
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
}

void instance_and_hostname_nsec_sections(const service_info &info)
{
    SECTION("NSEC owner is the instance name with SRV/TXT/NSEC bitmap")
    {
        auto nsec = planned_nsec(info, answer_plan{.nsec_service_name = true}, info.service_name);
        // rdata = owner name, window, length, bitmap; the bitmap flags TXT(16), SRV(33), NSEC(47)
        auto owner = wire_name(info.service_name).size();
        REQUIRE(nsec.rdata.size() > owner + 2);
        CHECK(rdata_byte(nsec, owner) == 0);
        REQUIRE(rdata_byte(nsec, owner + 1) == 6);
        CHECK(rdata_byte(nsec, owner + 2 + 2) == 0x80); // TXT(16)
        CHECK(rdata_byte(nsec, owner + 2 + 4) == 0x40); // SRV(33)
        CHECK(rdata_byte(nsec, owner + 2 + 5) == 0x01); // NSEC(47)
    }

    SECTION("NSEC owner is the hostname with only the existing address types")
    {
        auto nsec = planned_nsec(info, answer_plan{.nsec_hostname = true}, info.hostname);
        auto owner = wire_name(info.hostname).size();
        REQUIRE(nsec.rdata.size() > owner + 2);
        REQUIRE(rdata_byte(nsec, owner + 1) == 1); // only A(1) exists (no IPv6 configured)
        CHECK(rdata_byte(nsec, owner + 2) == 0x40); // A(1)
    }
}

void service_type_nsec_and_ttl_sections(const service_info &info)
{
    SECTION("NSEC owner is the service type with only the PTR bit")
    {
        auto nsec = planned_nsec(info, answer_plan{.nsec_service_type = true}, info.service_type);
        auto owner = wire_name(info.service_type).size();
        REQUIRE(rdata_byte(nsec, owner + 1) == 2);
        CHECK(rdata_byte(nsec, owner + 2 + 1) == 0x08); // PTR(12)
    }

    SECTION("uses per-type TTLs from service_options")
    {
        auto response = build_answer_response(info, answer_plan{.ptr = true}, uniform_ttls(std::chrono::seconds{1234}));
        auto rrs = collect_rrs(response);
        REQUIRE_FALSE(rrs.empty());
        for(const auto &rr : rrs)
            CHECK(rr.ttl == 1234);
    }
}

std::vector<std::byte> legacy_ptr_response(const service_info &info)
{
    std::vector<std::byte> questions;
    push_question(questions, info.service_type, dns_type::ptr, false);
    response_header_options hdr;
    hdr.id = 0x1234;
    hdr.cache_flush = false;
    hdr.include_nsec = false;
    hdr.ttl_cap = 10;
    hdr.questions = std::span<const std::byte>(questions);
    hdr.qdcount = 1;
    return build_answer_response(info, answer_plan{.ptr = true}, service_options{}, hdr);
}

void repeated_question_and_ttl_cap_sections(const service_info &info, const std::vector<std::byte> &response)
{
    SECTION("repeats the question")
    {
        CHECK(read_u16_be(response.data() + 4) == 1);
        auto name = read_dns_name(std::span<const std::byte>(response), 12);
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

}

TEST_CASE("build_answer_response", "[server_response_aggregation]")
{
    auto info = make_subtype_test_info();
    ptr_and_empty_plan_sections(info);
    instance_and_hostname_nsec_sections(info);
    service_type_nsec_and_ttl_sections(info);
}

TEST_CASE("build_answer_response legacy unicast framing (RFC 6762 section 6.7)",
          "[server_response_aggregation][legacy]")
{
    auto info = make_subtype_test_info();
    auto response = legacy_ptr_response(info);
    REQUIRE(response.size() >= 12);

    SECTION("repeats the query ID")
    {
        CHECK(read_u16_be(response.data()) == 0x1234);
    }

    repeated_question_and_ttl_cap_sections(info, response);
}

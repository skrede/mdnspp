// tests/server_known_answer_test.cpp
// Unit tests for detail::parse_known_answers and all_suppressed.

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_enums.h"
#include "mdnspp/detail/server_known_answer.h"

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
    info.address_ipv4 = "192.168.1.10";
    info.address_ipv6 = std::nullopt;
    return info;
}

// Build a packet with header (1 question placeholder) and answer records.
// offset_out: where the answer section starts.
//
// A PTR answer's rdata is the target instance name it points to (defaults to
// info.service_name, i.e. "this server's own instance"). RFC 6762 §7.1
// suppression keys on that target, so the test surface must carry a real PTR
// target rather than dummy bytes. Non-PTR answers keep minimal dummy rdata.
struct answer_spec
{
    std::string_view name;
    dns_type rtype;
    uint32_t ttl;
    std::string_view ptr_target{"MyApp._http._tcp.local."};
};

static std::vector<std::byte> build_answer_packet(
    std::initializer_list<answer_spec> answers,
    size_t &offset_out)
{
    std::vector<std::byte> pkt;

    // DNS header
    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x0000); // flags
    push_u16_be(pkt, 0x0001); // qdcount = 1
    push_u16_be(pkt, static_cast<uint16_t>(answers.size())); // ancount
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    // A dummy question section (so offset starts after it)
    auto qname = encode_dns_name("_http._tcp.local.");
    pkt.insert(pkt.end(), qname.begin(), qname.end());
    push_u16_be(pkt, mdnspp::detail::to_underlying(dns_type::ptr));
    push_u16_be(pkt, 0x0001); // IN class

    offset_out = pkt.size();

    // Answer records
    for(const auto &a : answers)
    {
        auto encoded_name = encode_dns_name(a.name);
        pkt.insert(pkt.end(), encoded_name.begin(), encoded_name.end());
        push_u16_be(pkt, mdnspp::detail::to_underlying(a.rtype));
        push_u16_be(pkt, 0x0001); // class IN
        push_u32_be(pkt, a.ttl);

        if(a.rtype == dns_type::ptr)
        {
            // Real PTR rdata: the encoded target instance name.
            auto target = encode_dns_name(a.ptr_target);
            push_u16_be(pkt, static_cast<uint16_t>(target.size()));
            pkt.insert(pkt.end(), target.begin(), target.end());
        }
        else
        {
            // Minimal rdata: 4 bytes dummy
            push_u16_be(pkt, 0x0004);
            pkt.push_back(std::byte{0x00});
            pkt.push_back(std::byte{0x00});
            pkt.push_back(std::byte{0x00});
            pkt.push_back(std::byte{0x00});
        }
    }

    return pkt;
}

TEST_CASE("parse_known_answers", "[server_known_answer]")
{
    auto info = make_test_info();

    SECTION("returns empty mask for no answers")
    {
        size_t offset;
        auto pkt = build_answer_packet({}, offset);
        // Override ancount to 0
        pkt[6] = std::byte{0};
        pkt[7] = std::byte{0};
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.ptr);
        CHECK_FALSE(mask.srv);
        CHECK_FALSE(mask.a);
        CHECK_FALSE(mask.aaaa);
        CHECK_FALSE(mask.txt);
    }

    SECTION("sets ptr=true for matching PTR answer naming our instance with TTL >= threshold")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 4500, "MyApp._http._tcp.local."}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK(mask.ptr);
        CHECK_FALSE(mask.srv);
    }

    SECTION("does NOT suppress a PTR answer naming a DIFFERENT instance")
    {
        // RFC 6762 §7.1: a browse query's known answers list the responder's own
        // instances. A PTR for some *other* node (same service type, different
        // target) must not suppress our PTR — otherwise a live-but-silent
        // responder never answers a peer's browse for the shared service type.
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 4500, "OtherApp._http._tcp.local."}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.ptr);
    }

    SECTION("ignores answers with TTL < threshold")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 1000}  // below 2250 threshold
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.ptr);
    }

    SECTION("ignores answers with non-matching names")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_other._tcp.local.", dns_type::ptr, 4500}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.ptr);
    }

    SECTION("sets srv=true for matching SRV answer")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"MyApp._http._tcp.local.", dns_type::srv, 4500}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK(mask.srv);
    }

    SECTION("sets a=true for matching A answer on hostname")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"myhost.local.", dns_type::a, 4500}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK(mask.a);
    }
}

TEST_CASE("parse_known_answers with custom threshold", "[server_known_answer]")
{
    auto info = make_test_info();

    SECTION("suppressed when TTL >= custom threshold")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 500}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info, 400);
        CHECK(mask.ptr);
    }

    SECTION("not suppressed when TTL < custom threshold")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 500}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info, 600);
        CHECK_FALSE(mask.ptr);
    }
}

TEST_CASE("all_suppressed", "[server_known_answer]")
{
    auto info = make_test_info();

    SECTION("returns true when all would-send types are suppressed")
    {
        suppression_mask mask{.ptr = true};
        CHECK(all_suppressed(mask, dns_type::ptr, info));
    }

    SECTION("returns false when any would-send type is not suppressed")
    {
        suppression_mask mask{.ptr = true, .srv = false};
        CHECK_FALSE(all_suppressed(mask, dns_type::any, info));
    }

    SECTION("handles dns_type::any correctly")
    {
        // info has ipv4 but no ipv6, so would send ptr, srv, a, txt
        suppression_mask mask{.ptr = true, .srv = true, .a = true, .txt = true};
        CHECK(all_suppressed(mask, dns_type::any, info));
    }

    SECTION("returns false for ANY when one type not suppressed")
    {
        suppression_mask mask{.ptr = true, .srv = true, .a = false, .txt = true};
        CHECK_FALSE(all_suppressed(mask, dns_type::any, info));
    }
}

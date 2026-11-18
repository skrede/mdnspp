// tests/server_known_answer_test.cpp
// Unit tests for detail::parse_known_answers (RFC 6762 §7.1 rdata-matching
// suppression), record_matches_ours, record_conflicts_ours and
// suppress_from_records.

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_read.h"
#include "mdnspp/detail/dns_write.h"
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

// Build a packet with header (1 question placeholder) and answer records
// carrying explicit rdata. RFC 6762 §7.1 suppression matches name, type,
// class AND rdata, so the test surface carries real rdata bytes.
struct answer_spec
{
    std::string_view name;
    dns_type rtype;
    uint32_t ttl;
    std::vector<std::byte> rdata;
};

static std::vector<std::byte> srv_rdata(uint16_t priority, uint16_t weight, uint16_t port,
                                        std::string_view target)
{
    std::vector<std::byte> rdata;
    push_u16_be(rdata, priority);
    push_u16_be(rdata, weight);
    push_u16_be(rdata, port);
    auto encoded = encode_dns_name(target).value();
    rdata.insert(rdata.end(), encoded.begin(), encoded.end());
    return rdata;
}

static std::vector<std::byte> a_rdata(const std::string &addr)
{
    return *encode_ipv4(addr);
}

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
    auto qname = encode_dns_name("_http._tcp.local.").value();
    pkt.insert(pkt.end(), qname.begin(), qname.end());
    push_u16_be(pkt, mdnspp::detail::to_underlying(dns_type::ptr));
    push_u16_be(pkt, 0x0001); // IN class

    offset_out = pkt.size();

    // Answer records
    for(const auto &a : answers)
    {
        auto encoded_name = encode_dns_name(a.name).value();
        pkt.insert(pkt.end(), encoded_name.begin(), encoded_name.end());
        push_u16_be(pkt, mdnspp::detail::to_underlying(a.rtype));
        push_u16_be(pkt, 0x0001); // class IN
        push_u32_be(pkt, a.ttl);
        push_u16_be(pkt, static_cast<uint16_t>(a.rdata.size()));
        pkt.insert(pkt.end(), a.rdata.begin(), a.rdata.end());
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
            {"_http._tcp.local.", dns_type::ptr, 4500, encode_dns_name("MyApp._http._tcp.local.").value()}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK(mask.ptr);
        CHECK_FALSE(mask.srv);
    }

    SECTION("suppresses case-variant answers (RFC 6762 section 16: comparison is case-insensitive)")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_HTTP._TCP.LOCAL.", dns_type::ptr, 4500, encode_dns_name("MYAPP._HTTP._TCP.LOCAL.").value()}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK(mask.ptr);
    }

    SECTION("does NOT suppress a PTR answer naming a DIFFERENT instance")
    {
        // RFC 6762 §7.1: a browse query's known answers list the responder's own
        // instances. A PTR for some *other* node (same service type, different
        // target) must not suppress our PTR — otherwise a live-but-silent
        // responder never answers a peer's browse for the shared service type.
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 4500, encode_dns_name("OtherApp._http._tcp.local.").value()}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.ptr);
    }

    SECTION("ignores answers with TTL < threshold")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 1000, encode_dns_name("MyApp._http._tcp.local.").value()}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.ptr);
    }

    SECTION("ignores answers with non-matching names")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_other._tcp.local.", dns_type::ptr, 4500, encode_dns_name("MyApp._http._tcp.local.").value()}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.ptr);
    }

    SECTION("sets srv=true for SRV answer with matching rdata")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"MyApp._http._tcp.local.", dns_type::srv, 4500,
             srv_rdata(0, 0, 8080, "myhost.local.")}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK(mask.srv);
    }

    SECTION("does NOT suppress an SRV answer with stale rdata (different port)")
    {
        // RFC 6762 §7.1: rdata must match — a querier holding a stale SRV
        // (old port) must still receive our correct answer.
        size_t offset;
        auto pkt = build_answer_packet({
            {"MyApp._http._tcp.local.", dns_type::srv, 4500,
             srv_rdata(0, 0, 9999, "myhost.local.")}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.srv);
    }

    SECTION("does NOT suppress an SRV answer owned by the hostname")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"myhost.local.", dns_type::srv, 4500,
             srv_rdata(0, 0, 8080, "myhost.local.")}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.srv);
    }

    SECTION("sets a=true for A answer with matching address on hostname")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"myhost.local.", dns_type::a, 4500, a_rdata("192.168.1.10")}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK(mask.a);
    }

    SECTION("does NOT suppress an A answer with a different address")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"myhost.local.", dns_type::a, 4500, a_rdata("10.0.0.99")}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info);
        CHECK_FALSE(mask.a);
    }

    SECTION("sets txt=true only for byte-identical TXT rdata")
    {
        auto info_txt = make_test_info();
        info_txt.txt_records = {service_txt{"path", "/api"}};
        auto matching = encode_txt_records(info_txt.txt_records);
        auto different = encode_txt_records({service_txt{"path", "/other"}});

        size_t offset;
        auto pkt = build_answer_packet({
            {"MyApp._http._tcp.local.", dns_type::txt, 4500, matching}
        }, offset);
        CHECK(parse_known_answers(std::span(pkt), offset, info_txt).txt);

        auto pkt2 = build_answer_packet({
            {"MyApp._http._tcp.local.", dns_type::txt, 4500, different}
        }, offset);
        CHECK_FALSE(parse_known_answers(std::span(pkt2), offset, info_txt).txt);
    }
}

TEST_CASE("parse_known_answers with custom per-type thresholds", "[server_known_answer]")
{
    auto info = make_test_info();

    SECTION("suppressed when TTL >= custom threshold")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 500, encode_dns_name("MyApp._http._tcp.local.").value()}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info, ka_thresholds{.ptr = 400});
        CHECK(mask.ptr);
    }

    SECTION("not suppressed when TTL < custom threshold")
    {
        size_t offset;
        auto pkt = build_answer_packet({
            {"_http._tcp.local.", dns_type::ptr, 500, encode_dns_name("MyApp._http._tcp.local.").value()}
        }, offset);
        auto mask = parse_known_answers(std::span(pkt), offset, info, ka_thresholds{.ptr = 600});
        CHECK_FALSE(mask.ptr);
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

TEST_CASE("record_matches_ours and record_conflicts_ours", "[server_known_answer]")
{
    auto info = make_test_info();

    SECTION("identical SRV matches and does not conflict")
    {
        record_srv srv;
        srv.name = "MyApp._http._tcp.local.";
        srv.port = 8080;
        srv.srv_name = "myhost.local.";
        CHECK(record_matches_ours(srv, info));
        CHECK_FALSE(record_conflicts_ours(srv, info));
    }

    SECTION("SRV with our name but different rdata conflicts (RFC 6762 section 9)")
    {
        record_srv srv;
        srv.name = "MyApp._http._tcp.local.";
        srv.port = 9999;
        srv.srv_name = "otherhost.local.";
        CHECK_FALSE(record_matches_ours(srv, info));
        CHECK(record_conflicts_ours(srv, info));
    }

    SECTION("SRV for a foreign name neither matches nor conflicts")
    {
        record_srv srv;
        srv.name = "Other._http._tcp.local.";
        srv.port = 8080;
        srv.srv_name = "myhost.local.";
        CHECK_FALSE(record_matches_ours(srv, info));
        CHECK_FALSE(record_conflicts_ours(srv, info));
    }

    SECTION("A record at our hostname with different address conflicts")
    {
        record_a a;
        a.name = "myhost.local.";
        a.address_string = "10.0.0.99";
        CHECK(record_conflicts_ours(a, info));
    }

    SECTION("PTR records are shared and never conflict")
    {
        record_ptr ptr;
        ptr.name = "_http._tcp.local.";
        ptr.ptr_name = "Other._http._tcp.local.";
        CHECK_FALSE(record_conflicts_ours(ptr, info));
    }
}

TEST_CASE("suppress_from_records applies per-type thresholds and rdata matching",
          "[server_known_answer]")
{
    auto info = make_test_info();

    record_ptr ptr;
    ptr.name = "_http._tcp.local.";
    ptr.ttl = 4500;
    ptr.ptr_name = "MyApp._http._tcp.local.";

    record_srv stale_srv;
    stale_srv.name = "MyApp._http._tcp.local.";
    stale_srv.ttl = 4500;
    stale_srv.port = 9999; // stale rdata — must NOT suppress
    stale_srv.srv_name = "myhost.local.";

    record_a low_ttl_a;
    low_ttl_a.name = "myhost.local.";
    low_ttl_a.ttl = 10; // below threshold — must NOT suppress
    low_ttl_a.address_string = "192.168.1.10";

    std::vector<mdns_record_variant> records{ptr, stale_srv, low_ttl_a};
    auto mask = suppress_from_records(records, info, ka_thresholds{.ptr = 2250, .srv = 60, .a = 60});

    CHECK(mask.ptr);
    CHECK_FALSE(mask.srv);
    CHECK_FALSE(mask.a);
}

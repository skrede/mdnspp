#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/byte_order.h"
#include "mdnspp/detail/server_tiebreak.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <string_view>

using namespace mdnspp::detail;

namespace {

std::vector<tiebreak_record> tiebreak_set(const mdnspp::service_info &info)
{
    std::vector<tiebreak_record> records;
    for(auto &rec : build_proposed_records(info))
        records.push_back(tiebreak_record{
            to_underlying(mdnspp::dns_class::in),
            to_underlying(rec.rtype),
            std::move(rec.rdata)});
    return records;
}

mdnspp::service_info tiebreak_info(uint16_t port, std::string_view host = "host-a.local.")
{
    mdnspp::service_info info;
    info.service_name = "Shared._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = std::string(host);
    info.port = port;
    info.address_ipv4 = "192.168.1.1";
    return info;
}

void push_question_pointer(std::vector<std::byte> &pkt)
{
    pkt.push_back(std::byte{0xC0});
    pkt.push_back(std::byte{12});
}

// A probe whose SRV owner and SRV target are both compression pointers to the question name at offset 12.
std::vector<std::byte> compressed_srv_probe(const mdnspp::service_info &info)
{
    std::vector<std::byte> pkt;
    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x0000); // flags
    push_u16_be(pkt, 0x0001); // qdcount
    push_u16_be(pkt, 0x0000); // ancount
    push_u16_be(pkt, 0x0001); // nscount
    push_u16_be(pkt, 0x0000); // arcount
    auto qname = encode_dns_name("Shared._http._tcp.local.").value();
    pkt.insert(pkt.end(), qname.begin(), qname.end());
    push_u16_be(pkt, to_underlying(mdnspp::dns_type::any));
    push_u16_be(pkt, 0x8001);
    push_question_pointer(pkt);
    push_u16_be(pkt, to_underlying(mdnspp::dns_type::srv));
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 8); // rdlength: 6 fixed + 2-byte pointer
    push_u16_be(pkt, info.priority);
    push_u16_be(pkt, info.weight);
    push_u16_be(pkt, info.port);
    push_question_pointer(pkt);
    return pkt;
}

// RFC 6762 §8.2.1 compares raw bytes, so the original byte case of the target is preserved.
std::vector<std::byte> uncompressed_srv_rdata(const mdnspp::service_info &info)
{
    std::vector<std::byte> expected;
    push_u16_be(expected, info.priority);
    push_u16_be(expected, info.weight);
    push_u16_be(expected, info.port);
    auto target = encode_dns_name("Shared._http._tcp.local.").value();
    expected.insert(expected.end(), target.begin(), target.end());
    return expected;
}

}

TEST_CASE("compare_record_sets: identical sets are an exact tie", "[tiebreak]")
{
    auto ours = tiebreak_set(tiebreak_info(8080));
    auto theirs = tiebreak_set(tiebreak_info(8080));
    CHECK(compare_record_sets(std::move(ours), std::move(theirs)) == 0);
}

TEST_CASE("compare_record_sets: lower SRV port loses", "[tiebreak]")
{
    auto low = tiebreak_set(tiebreak_info(8080));
    auto high = tiebreak_set(tiebreak_info(9090));
    CHECK(compare_record_sets(low, high) < 0);
    CHECK(compare_record_sets(high, low) > 0);
}

TEST_CASE("compare_record_sets: a record-set prefix loses to the longer set", "[tiebreak]")
{
    auto full = tiebreak_set(tiebreak_info(8080));
    // SRV (type 33) sorts last but is built first, so dropping it leaves a strict sorted prefix.
    auto prefix = full;
    prefix.erase(prefix.begin());
    CHECK(compare_record_sets(prefix, full) < 0);
    CHECK(compare_record_sets(full, prefix) > 0);
}

TEST_CASE("extract_authority_records round-trips the probe authority", "[tiebreak]")
{
    auto info = tiebreak_info(8080);
    auto probe = build_probe_query(info);
    REQUIRE_FALSE(probe.empty());

    auto theirs = extract_authority_records(std::span<const std::byte>(probe));
    REQUIRE_FALSE(theirs.empty());

    // A host receiving its own looped-back probe sees an exact tie, not a conflict.
    CHECK(compare_record_sets(tiebreak_set(info), std::move(theirs)) == 0);
}

TEST_CASE("extract_authority_records decompresses SRV target names", "[tiebreak]")
{
    auto info = tiebreak_info(8080, "shared._http._tcp.local.");
    auto pkt = compressed_srv_probe(info);

    auto theirs = extract_authority_records(std::span<const std::byte>(pkt));
    REQUIRE(theirs.size() == 1);

    auto expected = uncompressed_srv_rdata(info);
    CHECK(theirs[0].rtype == to_underlying(mdnspp::dns_type::srv));
    CHECK(theirs[0].rdata == expected);
}

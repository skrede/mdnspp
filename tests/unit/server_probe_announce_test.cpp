// tests/server_probe_announce_test.cpp
// Unit tests for detail::probe_announce_state, state transition functions,
// RFC 6762 §8.2.1 record-set tiebreaking, and §8.1 probe rate limiting.

#include "mdnspp/service_info.h"

#include "mdnspp/detail/dns_query.h"
#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <chrono>
#include <string>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <string_view>

using namespace mdnspp::detail;
using namespace std::chrono_literals;

TEST_CASE("begin_probing resets state", "[server_probe_announce]")
{
    probe_announce_state s;
    s.state = server_state::live;
    s.probe_count = 5;

    begin_probing(s);

    CHECK(s.state == server_state::probing);
    CHECK(s.probe_count == 0);
}

TEST_CASE("advance_probe increments count", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);

    SECTION("returns true when more probes needed")
    {
        CHECK(advance_probe(s));
        CHECK(s.probe_count == 1);
        CHECK(advance_probe(s));
        CHECK(s.probe_count == 2);
    }

    SECTION("returns false when count reaches 3")
    {
        advance_probe(s);
        advance_probe(s);
        CHECK_FALSE(advance_probe(s));
        CHECK(s.probe_count == 3);
    }
}

TEST_CASE("should_send_probe", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);

    CHECK(should_send_probe(s));
    advance_probe(s);
    advance_probe(s);
    advance_probe(s);
    CHECK_FALSE(should_send_probe(s));
}

TEST_CASE("probing_complete returns true at count >= 3", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);

    CHECK_FALSE(probing_complete(s));
    advance_probe(s);
    advance_probe(s);
    advance_probe(s);
    CHECK(probing_complete(s));
}

TEST_CASE("begin_announcing transitions state", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);
    advance_probe(s);
    advance_probe(s);
    advance_probe(s);

    begin_announcing(s);

    CHECK(s.state == server_state::announcing);
    CHECK(s.announce_count == 0);
}

TEST_CASE("advance_announce increments and respects max", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_announcing(s);

    SECTION("returns true when more needed")
    {
        CHECK(advance_announce(s, 3));
        CHECK(s.announce_count == 1);
    }

    SECTION("returns false at max count")
    {
        advance_announce(s, 2);
        CHECK_FALSE(advance_announce(s, 2));
        CHECK(s.announce_count == 2);
    }
}

TEST_CASE("should_send_announce", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_announcing(s);

    CHECK(should_send_announce(s, 2));
    advance_announce(s, 2);
    advance_announce(s, 2);
    CHECK_FALSE(should_send_announce(s, 2));
}

TEST_CASE("should_send_probe respects custom max_count", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);
    s.probe_count = 4;

    CHECK(should_send_probe(s, 5));
    CHECK_FALSE(should_send_probe(s, 4));
}

TEST_CASE("probing_complete with custom count", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);

    s.probe_count = 2;
    CHECK(probing_complete(s, 2));
    CHECK_FALSE(probing_complete(s, 3));
}

TEST_CASE("advance_probe with custom count", "[server_probe_announce]")
{
    probe_announce_state s;
    begin_probing(s);

    SECTION("returns true until count reaches max_count")
    {
        CHECK(advance_probe(s, 4)); // count == 1
        CHECK(advance_probe(s, 4)); // count == 2
        CHECK(advance_probe(s, 4)); // count == 3
        CHECK_FALSE(advance_probe(s, 4)); // count == 4, returns false
        CHECK(s.probe_count == 4);
    }
}

// ---------------------------------------------------------------------------
// RFC 6762 §8.2.1 tiebreaking over full record sets
// ---------------------------------------------------------------------------

static std::vector<tiebreak_record> tiebreak_set(const mdnspp::service_info &info)
{
    std::vector<tiebreak_record> records;
    for(auto &rec : build_proposed_records(info))
        records.push_back(tiebreak_record{
            to_underlying(mdnspp::dns_class::in),
            to_underlying(rec.rtype),
            std::move(rec.rdata)});
    return records;
}

static mdnspp::service_info tiebreak_info(uint16_t port, std::string_view host = "host-a.local.")
{
    mdnspp::service_info info;
    info.service_name = "Shared._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = std::string(host);
    info.port = port;
    info.address_ipv4 = "192.168.1.1";
    return info;
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
    // Remove the record that sorts LAST (SRV, type 33, first in build order)
    // so the remaining set is a strict sorted prefix of the full set.
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

    // The extracted set must compare equal to the locally built set: a host
    // receiving its own looped-back probe sees an exact tie, not a conflict.
    CHECK(compare_record_sets(tiebreak_set(info), std::move(theirs)) == 0);
}

TEST_CASE("extract_authority_records decompresses SRV target names", "[tiebreak]")
{
    // Hand-build a probe whose SRV rdata target is a compression pointer to
    // the question name, then verify the extracted rdata is uncompressed.
    auto info = tiebreak_info(8080, "shared._http._tcp.local.");

    std::vector<std::byte> pkt;
    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x0000); // flags
    push_u16_be(pkt, 0x0001); // qdcount
    push_u16_be(pkt, 0x0000); // ancount
    push_u16_be(pkt, 0x0001); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    auto qname = encode_dns_name("Shared._http._tcp.local.");
    pkt.insert(pkt.end(), qname.begin(), qname.end());
    push_u16_be(pkt, to_underlying(mdnspp::dns_type::any));
    push_u16_be(pkt, 0x8001);

    // Authority SRV: owner = pointer to question name (offset 12)
    pkt.push_back(std::byte{0xC0});
    pkt.push_back(std::byte{12});
    push_u16_be(pkt, to_underlying(mdnspp::dns_type::srv));
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 8); // rdlength: 6 fixed + 2-byte pointer
    push_u16_be(pkt, info.priority);
    push_u16_be(pkt, info.weight);
    push_u16_be(pkt, info.port);
    pkt.push_back(std::byte{0xC0}); // SRV target compressed to question name
    pkt.push_back(std::byte{12});

    auto theirs = extract_authority_records(std::span<const std::byte>(pkt));
    REQUIRE(theirs.size() == 1);

    // Expected uncompressed rdata: fixed fields + full encoded target name.
    // §8.2.1 compares raw bytes, so the original byte case is preserved.
    std::vector<std::byte> expected;
    push_u16_be(expected, info.priority);
    push_u16_be(expected, info.weight);
    push_u16_be(expected, info.port);
    auto target = encode_dns_name("Shared._http._tcp.local.");
    expected.insert(expected.end(), target.begin(), target.end());

    CHECK(theirs[0].rtype == to_underlying(mdnspp::dns_type::srv));
    CHECK(theirs[0].rdata == expected);
}

// ---------------------------------------------------------------------------
// RFC 6762 §8.1 probe rate limiting
// ---------------------------------------------------------------------------

namespace {

struct rate_clock_guard
{
    rate_clock_guard() { mdnspp::testing::test_clock::reset(); }
    ~rate_clock_guard() { mdnspp::testing::test_clock::reset(); }
};

using rate_limiter = probe_rate_limiter<mdnspp::testing::test_clock>;

}

TEST_CASE("probe_rate_limiter stays unthrottled below 15 conflicts", "[rate-limit]")
{
    rate_clock_guard cg;
    rate_limiter rl;

    for(std::size_t i = 0; i < rate_limiter::conflict_threshold - 1; ++i)
        rl.record_conflict();

    CHECK_FALSE(rl.throttled());
}

TEST_CASE("probe_rate_limiter throttles at 15 conflicts within 10 s", "[rate-limit]")
{
    rate_clock_guard cg;
    rate_limiter rl;

    for(std::size_t i = 0; i < rate_limiter::conflict_threshold; ++i)
    {
        rl.record_conflict();
        mdnspp::testing::test_clock::advance(100ms); // 1.5 s total, well within 10 s
    }

    CHECK(rl.throttled());
}

TEST_CASE("probe_rate_limiter does not throttle when conflicts are spread beyond the window", "[rate-limit]")
{
    rate_clock_guard cg;
    rate_limiter rl;

    for(std::size_t i = 0; i < rate_limiter::conflict_threshold; ++i)
    {
        rl.record_conflict();
        mdnspp::testing::test_clock::advance(1s); // 15 s total; window prunes
    }

    CHECK_FALSE(rl.throttled());
}

TEST_CASE("probe_rate_limiter disengages after the window drains", "[rate-limit]")
{
    rate_clock_guard cg;
    rate_limiter rl;

    for(std::size_t i = 0; i < rate_limiter::conflict_threshold; ++i)
        rl.record_conflict();

    REQUIRE(rl.throttled());

    // Still conflicts within the window: stays throttled.
    mdnspp::testing::test_clock::advance(5s);
    CHECK(rl.throttled());

    // Window fully drained: throttle disengages.
    mdnspp::testing::test_clock::advance(6s);
    CHECK_FALSE(rl.throttled());
}

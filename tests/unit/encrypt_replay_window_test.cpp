// tests/unit/encrypt_replay_window_test.cpp
// Unit tests for the anti-replay sliding window (RFC 4303 algorithm).

#include "mdnspp/encrypt/replay_window.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("replay_window: first packet is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    auto result = rw.check_and_record(1, 1);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("replay_window: replayed sequence number is rejected", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    REQUIRE_FALSE(rw.check_and_record(1, 1).has_value());
    auto result = rw.check_and_record(1, 1);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("replay_window: next sequence number is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    REQUIRE_FALSE(rw.check_and_record(1, 1).has_value());
    auto result = rw.check_and_record(1, 2);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("replay_window: jump ahead then within window is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1).has_value());
    // Jump to 100 — accepted
    REQUIRE_FALSE(rw.check_and_record(1, 100).has_value());
    // seq=50 is within window [37..99], not yet seen — accepted
    REQUIRE_FALSE(rw.check_and_record(1, 50).has_value());
}

TEST_CASE("replay_window: seq within window not yet seen is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    // max_seq = 100, window covers (100 - 64, 100] = (36, 100]
    REQUIRE_FALSE(rw.check_and_record(1, 100).has_value());
    // seq=30 is outside window (100 - 64 = 36, so 30 <= 36) — too old
    // Note: plan tests say seq=30 with window=64 is within window when max=100.
    // Window covers seq > max_seq - window_size, i.e. seq > 36. seq=37..99 is within.
    // seq=37 first time — accepted
    auto result = rw.check_and_record(1, 37);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("replay_window: seq within window accepted then replayed is rejected", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 100).has_value());
    // seq=37 is within window (37 > 100-64 = 36) — first time accepted
    REQUIRE_FALSE(rw.check_and_record(1, 37).has_value());
    // seq=37 again — replay
    auto result = rw.check_and_record(1, 37);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("replay_window: seq too old (outside window) is rejected", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 100).has_value());
    // seq=1 is <= max_seq - window_size = 36 — too old
    auto result = rw.check_and_record(1, 1);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("replay_window: different sender_ids have independent windows", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    // sender=1 accepts seq=1
    REQUIRE_FALSE(rw.check_and_record(1, 1).has_value());
    // sender=2 also accepts seq=1 independently
    REQUIRE_FALSE(rw.check_and_record(2, 1).has_value());
    // sender=1 rejects duplicate seq=1
    auto result = rw.check_and_record(1, 1);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("replay_window: LRU eviction when max_senders exceeded", "[encrypt][replay_window]")
{
    // max_senders=2: add sender=1, sender=2, sender=3 -> sender=1 (oldest) is evicted
    mdnspp::encrypt::replay_window rw(64, 2);
    REQUIRE_FALSE(rw.check_and_record(1, 10).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 10).has_value());
    // Adding sender=3 should evict sender=1
    REQUIRE_FALSE(rw.check_and_record(3, 10).has_value());
    // sender=2 and sender=3 still work
    REQUIRE_FALSE(rw.check_and_record(2, 11).has_value());
    REQUIRE_FALSE(rw.check_and_record(3, 11).has_value());
}

TEST_CASE("replay_window: after eviction, sender returns as new (fresh window)", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64, 2);
    REQUIRE_FALSE(rw.check_and_record(1, 10).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 10).has_value());
    // Evict sender=1 by adding sender=3
    REQUIRE_FALSE(rw.check_and_record(3, 10).has_value());
    // sender=1 re-enters with a fresh window; seq=10 is accepted (new sender state)
    auto result = rw.check_and_record(1, 10);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("replay_window: sequence 0 is valid as first sequence number", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    auto result = rw.check_and_record(1, 0);
    REQUIRE_FALSE(result.has_value());
    // seq=0 again is replay
    auto result2 = rw.check_and_record(1, 0);
    REQUIRE(result2.has_value());
    REQUIRE(result2.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("replay_window: window advances correctly with large sequence gaps", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1).has_value());
    // Jump by 1000
    REQUIRE_FALSE(rw.check_and_record(1, 1001).has_value());
    // seq=2 is far outside the new window (1001-64=937) — rejected
    auto result = rw.check_and_record(1, 2);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
    // seq=1001 is replay
    auto result2 = rw.check_and_record(1, 1001);
    REQUIRE(result2.has_value());
    REQUIRE(result2.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("replay_window: reset clears all state", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    REQUIRE_FALSE(rw.check_and_record(1, 100).has_value());
    // Without reset, seq=1 would be too old (window boundary at 100-64=36)
    REQUIRE(rw.check_and_record(1, 1).has_value());
    rw.reset();
    // After reset, seq=1 is accepted again as a fresh first packet
    REQUIRE_FALSE(rw.check_and_record(1, 1).has_value());
}

TEST_CASE("replay_window: LRU touch keeps recently-used sender alive", "[encrypt][replay_window]")
{
    // With max_senders=2, touching sender=1 after sender=2 is added
    // means sender=2 becomes the oldest, not sender=1
    mdnspp::encrypt::replay_window rw(64, 2);
    REQUIRE_FALSE(rw.check_and_record(1, 10).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 10).has_value());
    // Touch sender=1 again (making sender=2 oldest)
    REQUIRE_FALSE(rw.check_and_record(1, 11).has_value());
    // Adding sender=3 evicts sender=2 (oldest), not sender=1
    REQUIRE_FALSE(rw.check_and_record(3, 10).has_value());
    // sender=1 still has its window intact (seq=10 was already recorded)
    auto result = rw.check_and_record(1, 10);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

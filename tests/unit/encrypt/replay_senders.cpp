#include "mdnspp/encrypt/replay_window.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("different sender_ids have independent windows", "[encrypt][replay_window]")
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

TEST_CASE("LRU eviction when max_senders exceeded", "[encrypt][replay_window]")
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

TEST_CASE("after eviction, sender returns as new (fresh window)", "[encrypt][replay_window]")
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

TEST_CASE("LRU touch keeps recently-used sender alive", "[encrypt][replay_window]")
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

#include "mdnspp/encrypt/replay_window.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

TEST_CASE("window size 1 tracks only the maximum", "[encrypt][replay_window][bounds]")
{
    mdnspp::encrypt::replay_window rw(1);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 5).has_value());
    // seq=5 again is a replay
    REQUIRE(rw.check_and_record(1, 1, 5).has_value());
    // seq=4: diff = 1 >= window_size = 1 — too old
    REQUIRE(rw.check_and_record(1, 1, 4).has_value());
    // seq=6 advances
    REQUIRE_FALSE(rw.check_and_record(1, 1, 6).has_value());
    // seq=5: diff = 1 — too old again
    REQUIRE(rw.check_and_record(1, 1, 5).has_value());
}

TEST_CASE("window size 0 is clamped to 1", "[encrypt][replay_window][bounds]")
{
    mdnspp::encrypt::replay_window rw(0);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 10).has_value());
    REQUIRE(rw.check_and_record(1, 1, 10).has_value());
    // diff = 1 with effective window 1 — too old, but no shift UB
    REQUIRE(rw.check_and_record(1, 1, 9).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, 11).has_value());
}

TEST_CASE("window size 64 boundary distances", "[encrypt][replay_window][bounds]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1000).has_value());
    // diff = 63 == size - 1: inside the window, first occurrence — accepted
    REQUIRE_FALSE(rw.check_and_record(1, 1, 937).has_value());
    // diff = 63 replayed — rejected
    REQUIRE(rw.check_and_record(1, 1, 937).has_value());
    // diff = 64 == size: outside the window — rejected
    REQUIRE(rw.check_and_record(1, 1, 936).has_value());
    // diff = 65 == size + 1: outside the window — rejected
    REQUIRE(rw.check_and_record(1, 1, 935).has_value());
}

TEST_CASE("window size 128 boundary distances", "[encrypt][replay_window][bounds]")
{
    // 128 slots span two uint64_t words; diff in [64, 127] exercises the second
    // word, which was undefined behaviour with the previous single-word bitmap.
    mdnspp::encrypt::replay_window rw(128);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1000).has_value());
    // diff = 64: first bit of the second word — accepted then replay-rejected
    REQUIRE_FALSE(rw.check_and_record(1, 1, 936).has_value());
    REQUIRE(rw.check_and_record(1, 1, 936).has_value());
    // diff = 127 == size - 1 — accepted then replay-rejected
    REQUIRE_FALSE(rw.check_and_record(1, 1, 873).has_value());
    REQUIRE(rw.check_and_record(1, 1, 873).has_value());
    // diff = 128 == size — rejected
    REQUIRE(rw.check_and_record(1, 1, 872).has_value());
    // diff = 129 == size + 1 — rejected
    REQUIRE(rw.check_and_record(1, 1, 871).has_value());
}

TEST_CASE("window size 128 advance shifts bits across words", "[encrypt][replay_window][bounds]")
{
    mdnspp::encrypt::replay_window rw(128);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1000).has_value());
    // Advance by 100: the bit for seq 1000 moves from position 0 to position 100
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1100).has_value());
    // seq = 1000 (diff = 100, second word) was seen — replay
    REQUIRE(rw.check_and_record(1, 1, 1000).has_value());
    // seq = 1001 (diff = 99) was never seen — accepted
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1001).has_value());
}

TEST_CASE("sequence values near the top of the 64-bit space", "[encrypt][replay_window][wraparound]")
{
    mdnspp::encrypt::replay_window rw(64);
    const uint64_t top = UINT64_MAX;
    REQUIRE_FALSE(rw.check_and_record(1, 1, top - 1).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, top).has_value());
    REQUIRE(rw.check_and_record(1, 1, top).has_value());
    // The sequence space does not wrap: a small value after the top is simply too old.
    REQUIRE(rw.check_and_record(1, 1, 10).has_value());
}

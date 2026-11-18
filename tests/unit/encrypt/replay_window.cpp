#include "mdnspp/encrypt/replay_window.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("first packet is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    auto result = rw.check_and_record(1, 1, 1);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("replayed sequence number is rejected", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1).has_value());
    auto result = rw.check_and_record(1, 1, 1);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("next sequence number is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1).has_value());
    auto result = rw.check_and_record(1, 1, 2);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("jump ahead then within window is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1).has_value());
    // Jump to 100 — accepted
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    // seq=50 is within window [37..99], not yet seen — accepted
    REQUIRE_FALSE(rw.check_and_record(1, 1, 50).has_value());
}

TEST_CASE("seq within window not yet seen is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    // max_seq = 100, window covers (100 - 64, 100] = (36, 100]
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    // The window covers seq > max_seq - window_size, i.e. seq > 36; 37 is the oldest accepted.
    auto result = rw.check_and_record(1, 1, 37);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("seq within window accepted then replayed is rejected", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    // seq=37 is within window (37 > 100-64 = 36) — first time accepted
    REQUIRE_FALSE(rw.check_and_record(1, 1, 37).has_value());
    // seq=37 again — replay
    auto result = rw.check_and_record(1, 1, 37);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("seq too old (outside window) is rejected", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    // seq=1 is <= max_seq - window_size = 36 — too old
    auto result = rw.check_and_record(1, 1, 1);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("sequence 0 is valid as first sequence number", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    auto result = rw.check_and_record(1, 1, 0);
    REQUIRE_FALSE(result.has_value());
    // seq=0 again is replay
    auto result2 = rw.check_and_record(1, 1, 0);
    REQUIRE(result2.has_value());
    REQUIRE(result2.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("window advances correctly with large sequence gaps", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1).has_value());
    // Jump by 1000
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1001).has_value());
    // seq=2 is far outside the new window (1001-64=937) — rejected
    auto result = rw.check_and_record(1, 1, 2);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
    // seq=1001 is replay
    auto result2 = rw.check_and_record(1, 1, 1001);
    REQUIRE(result2.has_value());
    REQUIRE(result2.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("reset clears all state", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    // Without reset, seq=1 would be too old (window boundary at 100-64=36)
    REQUIRE(rw.check_and_record(1, 1, 1).has_value());
    rw.reset();
    // After reset, seq=1 is accepted again as a fresh first packet
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1).has_value());
}

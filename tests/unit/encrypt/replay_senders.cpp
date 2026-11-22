#include "mdnspp/encrypt/replay_window.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("different sender_ids have independent windows", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 1, 1).has_value());
    auto result = rw.check_and_record(1, 1, 1);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("LRU eviction when max_senders exceeded", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64, 2);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 10).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 1, 10).has_value());
    // evicts sender 1, the oldest
    REQUIRE_FALSE(rw.check_and_record(3, 1, 10).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 1, 11).has_value());
    REQUIRE_FALSE(rw.check_and_record(3, 1, 11).has_value());
}

TEST_CASE("after eviction, sender returns as new (fresh window)", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64, 2);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 10).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 1, 10).has_value());
    // evicts sender 1
    REQUIRE_FALSE(rw.check_and_record(3, 1, 10).has_value());
    auto result = rw.check_and_record(1, 1, 10);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("LRU touch keeps recently-used sender alive", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64, 2);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 10).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 1, 10).has_value());
    // sender 2 becomes the oldest
    REQUIRE_FALSE(rw.check_and_record(1, 1, 11).has_value());
    // evicts sender 2, not sender 1
    REQUIRE_FALSE(rw.check_and_record(3, 1, 10).has_value());
    auto result = rw.check_and_record(1, 1, 10);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

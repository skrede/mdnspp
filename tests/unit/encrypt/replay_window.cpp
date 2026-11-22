#include "mdnspp/encrypt/replay_window.h"

#include <catch2/catch_test_macros.hpp>

#include <type_traits>

static_assert(!std::is_copy_constructible_v<mdnspp::encrypt::replay_window>,
              "a copied replay window would hold iterators into the source window's sender list");
static_assert(!std::is_copy_assignable_v<mdnspp::encrypt::replay_window>,
              "a copy-assigned replay window would hold iterators into the source window's sender list");

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
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, 50).has_value());
}

TEST_CASE("seq within window not yet seen is accepted", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    // The window covers seq > max_seq - window_size, i.e. seq > 36; 37 is the oldest accepted.
    auto result = rw.check_and_record(1, 1, 37);
    REQUIRE_FALSE(result.has_value());
}

TEST_CASE("seq within window accepted then replayed is rejected", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, 37).has_value());
    auto result = rw.check_and_record(1, 1, 37);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("seq too old (outside window) is rejected", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    // 1 <= max_seq - window_size = 36
    auto result = rw.check_and_record(1, 1, 1);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("sequence 0 is valid as first sequence number", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    auto result = rw.check_and_record(1, 1, 0);
    REQUIRE_FALSE(result.has_value());
    auto result2 = rw.check_and_record(1, 1, 0);
    REQUIRE(result2.has_value());
    REQUIRE(result2.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("window advances correctly with large sequence gaps", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1001).has_value());
    auto result = rw.check_and_record(1, 1, 2);
    REQUIRE(result.has_value());
    REQUIRE(result.value() == mdnspp::encrypt::encrypt_error::replay_detected);
    auto result2 = rw.check_and_record(1, 1, 1001);
    REQUIRE(result2.has_value());
    REQUIRE(result2.value() == mdnspp::encrypt::encrypt_error::replay_detected);
}

TEST_CASE("reset clears all state", "[encrypt][replay_window]")
{
    mdnspp::encrypt::replay_window rw;
    REQUIRE_FALSE(rw.check_and_record(1, 1, 100).has_value());
    REQUIRE(rw.check_and_record(1, 1, 1).has_value());
    rw.reset();
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1).has_value());
}

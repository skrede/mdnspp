#include "mdnspp/encrypt/replay_window.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <system_error>

using mdnspp::encrypt::replay_window;

namespace {

std::error_code construct_error(uint16_t window_size, uint16_t max_senders, uint16_t max_sessions)
{
    std::error_code ec = std::make_error_code(std::errc::io_error);
    const replay_window rw(window_size, max_senders, max_sessions, ec);
    return ec;
}

std::error_code construct_exception(uint16_t window_size, uint16_t max_senders, uint16_t max_sessions)
{
    try
    {
        const replay_window rw(window_size, max_senders, max_sessions);
    }
    catch(const std::system_error &e)
    {
        return e.code();
    }
    return {};
}

}

TEST_CASE("window size 1 tracks only the maximum", "[encrypt][replay_window][bounds]")
{
    mdnspp::encrypt::replay_window rw(1);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 5).has_value());
    REQUIRE(rw.check_and_record(1, 1, 5).has_value());
    // diff = 1 >= window_size
    REQUIRE(rw.check_and_record(1, 1, 4).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, 6).has_value());
    REQUIRE(rw.check_and_record(1, 1, 5).has_value());
}

TEST_CASE("the error_code constructor reports a zero limit as invalid_argument", "[encrypt][replay_window][bounds]")
{
    CHECK(construct_error(0, 256, 8) == std::errc::invalid_argument);
    CHECK(construct_error(64, 0, 8) == std::errc::invalid_argument);
    CHECK(construct_error(64, 256, 0) == std::errc::invalid_argument);
    CHECK_FALSE(construct_error(64, 256, 8));
}

TEST_CASE("the throwing constructor throws invalid_argument for a zero limit", "[encrypt][replay_window][bounds]")
{
    CHECK(construct_exception(0, 256, 8) == std::errc::invalid_argument);
    CHECK(construct_exception(64, 0, 8) == std::errc::invalid_argument);
    CHECK(construct_exception(64, 256, 0) == std::errc::invalid_argument);
    CHECK_FALSE(construct_exception(64, 256, 8));
    CHECK_NOTHROW(replay_window{});
}

TEST_CASE("window size 64 boundary distances", "[encrypt][replay_window][bounds]")
{
    mdnspp::encrypt::replay_window rw(64);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1000).has_value());
    // diff = 63 == size - 1
    REQUIRE_FALSE(rw.check_and_record(1, 1, 937).has_value());
    REQUIRE(rw.check_and_record(1, 1, 937).has_value());
    // diff = 64 == size
    REQUIRE(rw.check_and_record(1, 1, 936).has_value());
    // diff = 65 == size + 1
    REQUIRE(rw.check_and_record(1, 1, 935).has_value());
}

TEST_CASE("window size 128 boundary distances", "[encrypt][replay_window][bounds]")
{
    // 128 slots span two uint64_t words; a diff in [64, 127] exercises the second word.
    mdnspp::encrypt::replay_window rw(128);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1000).has_value());
    // diff = 64: first bit of the second word
    REQUIRE_FALSE(rw.check_and_record(1, 1, 936).has_value());
    REQUIRE(rw.check_and_record(1, 1, 936).has_value());
    // diff = 127 == size - 1
    REQUIRE_FALSE(rw.check_and_record(1, 1, 873).has_value());
    REQUIRE(rw.check_and_record(1, 1, 873).has_value());
    // diff = 128 == size
    REQUIRE(rw.check_and_record(1, 1, 872).has_value());
    // diff = 129 == size + 1
    REQUIRE(rw.check_and_record(1, 1, 871).has_value());
}

TEST_CASE("window size 128 advance shifts bits across words", "[encrypt][replay_window][bounds]")
{
    mdnspp::encrypt::replay_window rw(128);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1000).has_value());
    // The bit for seq 1000 moves from position 0 to position 100, in the second word.
    REQUIRE_FALSE(rw.check_and_record(1, 1, 1100).has_value());
    REQUIRE(rw.check_and_record(1, 1, 1000).has_value());
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

TEST_CASE("a reported zero window size behaves as window size 1", "[encrypt][replay_window][bounds]")
{
    std::error_code ec;
    replay_window rw(0, 256, 8, ec);
    REQUIRE(ec == std::errc::invalid_argument);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 10).has_value());
    REQUIRE(rw.check_and_record(1, 1, 10).has_value());
    REQUIRE(rw.check_and_record(1, 1, 9).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, 11).has_value());
}

TEST_CASE("a reported zero sender limit keeps one sender", "[encrypt][replay_window][bounds]")
{
    std::error_code ec;
    replay_window rw(64, 0, 8, ec);
    REQUIRE(ec == std::errc::invalid_argument);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 5).has_value());
    REQUIRE(rw.check_and_record(1, 1, 5).has_value());
    REQUIRE_FALSE(rw.check_and_record(2, 1, 5).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, 5).has_value());
}

TEST_CASE("a reported zero session limit keeps one session per sender", "[encrypt][replay_window][bounds]")
{
    std::error_code ec;
    replay_window rw(64, 256, 0, ec);
    REQUIRE(ec == std::errc::invalid_argument);
    REQUIRE_FALSE(rw.check_and_record(1, 1, 5).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 2, 5).has_value());
    REQUIRE_FALSE(rw.check_and_record(1, 1, 5).has_value());
}

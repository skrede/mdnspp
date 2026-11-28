#include "helpers.h"

#include "mdnspp/encrypt/replay_window.h"

#include <catch2/catch_test_macros.hpp>

#include <system_error>

namespace {

using mdnspp::encrypt::replay_window;

bool accepted(replay_window &rw, uint32_t sender, uint64_t session, uint64_t sequence)
{
    return !rw.check_and_record(sender, session, sequence).has_value();
}

}

TEST_CASE("interleaved sessions of one sender keep independent windows", "[encrypt][replay_window][session]")
{
    replay_window rw(64, 256, 8);

    CHECK(accepted(rw, 1, 10, 5));
    CHECK(accepted(rw, 1, 20, 5));
    CHECK(accepted(rw, 1, 10, 6));
    CHECK(accepted(rw, 1, 20, 6));

    CHECK_FALSE(accepted(rw, 1, 10, 5));
    CHECK_FALSE(accepted(rw, 1, 20, 5));
    CHECK_FALSE(accepted(rw, 1, 10, 6));
    CHECK_FALSE(accepted(rw, 1, 20, 6));
}

TEST_CASE("advancing one session never resets another", "[encrypt][replay_window][session]")
{
    replay_window rw(64, 256, 8);
    REQUIRE(accepted(rw, 1, 10, 100));
    REQUIRE(accepted(rw, 1, 20, 1));

    CHECK(accepted(rw, 1, 20, uint64_t{1} << 50));
    CHECK_FALSE(accepted(rw, 1, 10, 100));
    CHECK(accepted(rw, 1, 10, 101));
}

TEST_CASE("an unseen session with a low sequence is accepted after a high-sequence session",
          "[encrypt][replay_window][session]")
{
    replay_window rw(64, 256, 8);
    REQUIRE(accepted(rw, 1, 10, uint64_t{1} << 40));

    CHECK(accepted(rw, 1, 20, 1));
    CHECK_FALSE(accepted(rw, 1, 20, 1));
}

TEST_CASE("the least recently used session is evicted and its replay is accepted once",
          "[encrypt][replay_window][session]")
{
    replay_window rw(64, 256, 2);
    REQUIRE(accepted(rw, 1, 10, 7));
    REQUIRE(accepted(rw, 1, 20, 7));
    REQUIRE(accepted(rw, 1, 30, 7));

    CHECK_FALSE(accepted(rw, 1, 20, 7));
    CHECK_FALSE(accepted(rw, 1, 30, 7));
    CHECK(accepted(rw, 1, 10, 7));
    CHECK_FALSE(accepted(rw, 1, 10, 7));
}

TEST_CASE("using a session keeps it from being evicted", "[encrypt][replay_window][session]")
{
    replay_window rw(64, 256, 2);
    REQUIRE(accepted(rw, 1, 10, 7));
    REQUIRE(accepted(rw, 1, 20, 7));
    REQUIRE(accepted(rw, 1, 10, 8));
    REQUIRE(accepted(rw, 1, 30, 7));

    CHECK_FALSE(accepted(rw, 1, 10, 7));
    CHECK_FALSE(accepted(rw, 1, 10, 8));
}

TEST_CASE("sender eviction drops every session of the evicted sender", "[encrypt][replay_window][session]")
{
    replay_window rw(64, 2, 2);
    REQUIRE(accepted(rw, 1, 10, 7));
    REQUIRE(accepted(rw, 1, 20, 7));
    REQUIRE(accepted(rw, 2, 10, 7));
    REQUIRE(accepted(rw, 3, 10, 7));

    CHECK_FALSE(accepted(rw, 2, 10, 7));
    CHECK_FALSE(accepted(rw, 3, 10, 7));
    CHECK(accepted(rw, 1, 10, 7));
    CHECK(accepted(rw, 1, 20, 7));
}

TEST_CASE("the same session id under different senders is tracked separately", "[encrypt][replay_window][session]")
{
    replay_window rw(64, 256, 8);

    CHECK(accepted(rw, 1, 10, 7));
    CHECK(accepted(rw, 2, 10, 7));
    CHECK_FALSE(accepted(rw, 1, 10, 7));
}

TEST_CASE("a session limit of zero is rejected by option validation", "[encrypt][replay_window][session]")
{
    auto opts = make_test_opts().encrypt;
    CHECK_FALSE(opts.validate());

    opts.max_sessions_per_sender = 0;

    CHECK(opts.validate() == std::make_error_code(std::errc::invalid_argument));
}

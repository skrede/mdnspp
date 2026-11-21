#include "mdnspp/detail/server_probe_announce.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>

using namespace mdnspp::detail;
using namespace std::chrono_literals;

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

    mdnspp::testing::test_clock::advance(5s);
    CHECK(rl.throttled());

    mdnspp::testing::test_clock::advance(6s);
    CHECK_FALSE(rl.throttled());
}

#include "mdnspp/mdns_options.h"
#include "mdnspp/detail/ttl_refresh.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <optional>
#include <random>

using namespace mdnspp;
using namespace mdnspp::detail;
using namespace std::chrono_literals;
using test_clock = mdnspp::testing::test_clock;

namespace {

struct clock_guard
{
    clock_guard()  { test_clock::reset(); }
    ~clock_guard() { test_clock::reset(); }
};

// Seed that produces zero jitter for the default jitter range — we brute-force
// determinism by setting refresh_jitter_pct = 0.0 instead.
mdns_options zero_jitter_opts()
{
    return mdns_options{.refresh_jitter_pct = 0.0};
}

}

TEST_CASE("make_refresh_schedule produces fire points at threshold fractions of TTL", "[ttl_refresh]")
{
    clock_guard cg;
    // wire_ttl=100s, zero jitter, default thresholds {0.80, 0.85, 0.90, 0.95}
    auto opts = zero_jitter_opts();
    auto inserted_at = test_clock::now();
    std::mt19937 rng{42};

    auto sched = make_refresh_schedule<test_clock>(100u, opts, inserted_at, rng);

    REQUIRE(sched.fire_at.size() == 4);
    CHECK(sched.fire_at[0] == inserted_at + 80000ms);
    CHECK(sched.fire_at[1] == inserted_at + 85000ms);
    CHECK(sched.fire_at[2] == inserted_at + 90000ms);
    CHECK(sched.fire_at[3] == inserted_at + 95000ms);
}

TEST_CASE("make_refresh_schedule for standard mDNS TTL 4500s", "[ttl_refresh]")
{
    clock_guard cg;
    auto opts = zero_jitter_opts();
    auto inserted_at = test_clock::now();
    std::mt19937 rng{42};

    // 4500s * 0.80 = 3600s, * 0.85 = 3825s, * 0.90 = 4050s, * 0.95 = 4275s
    auto sched = make_refresh_schedule<test_clock>(4500u, opts, inserted_at, rng);

    REQUIRE(sched.fire_at.size() == 4);
    CHECK(sched.fire_at[0] == inserted_at + 3600000ms);
    CHECK(sched.fire_at[1] == inserted_at + 3825000ms);
    CHECK(sched.fire_at[2] == inserted_at + 4050000ms);
    CHECK(sched.fire_at[3] == inserted_at + 4275000ms);
}

TEST_CASE("make_refresh_schedule with custom thresholds produces correct point count", "[ttl_refresh]")
{
    clock_guard cg;
    mdns_options opts{
        .ttl_refresh_thresholds = {0.50, 0.75},
        .refresh_jitter_pct     = 0.0,
    };
    auto inserted_at = test_clock::now();
    std::mt19937 rng{42};

    auto sched = make_refresh_schedule<test_clock>(100u, opts, inserted_at, rng);

    REQUIRE(sched.fire_at.size() == 2);
    CHECK(sched.fire_at[0] == inserted_at + 50000ms);
    CHECK(sched.fire_at[1] == inserted_at + 75000ms);
}

TEST_CASE("next_refresh_point advances through schedule", "[ttl_refresh]")
{
    clock_guard cg;
    auto opts = zero_jitter_opts();
    auto inserted_at = test_clock::now();
    std::mt19937 rng{42};

    auto sched = make_refresh_schedule<test_clock>(100u, opts, inserted_at, rng);

    // First call returns the first fire point
    auto p0 = next_refresh_point(sched);
    REQUIRE(p0.has_value());
    CHECK(*p0 == inserted_at + 80000ms);

    // Second call returns second fire point
    auto p1 = next_refresh_point(sched);
    REQUIRE(p1.has_value());
    CHECK(*p1 == inserted_at + 85000ms);
}

TEST_CASE("has_pending returns false after all points consumed", "[ttl_refresh]")
{
    clock_guard cg;
    mdns_options opts{
        .ttl_refresh_thresholds = {0.50},
        .refresh_jitter_pct     = 0.0,
    };
    auto inserted_at = test_clock::now();
    std::mt19937 rng{42};

    auto sched = make_refresh_schedule<test_clock>(100u, opts, inserted_at, rng);

    CHECK(has_pending(sched));
    static_cast<void>(next_refresh_point(sched));
    CHECK_FALSE(has_pending(sched));
}

TEST_CASE("next_refresh_point returns nullopt when schedule exhausted", "[ttl_refresh]")
{
    clock_guard cg;
    mdns_options opts{
        .ttl_refresh_thresholds = {0.50},
        .refresh_jitter_pct     = 0.0,
    };
    auto inserted_at = test_clock::now();
    std::mt19937 rng{42};

    auto sched = make_refresh_schedule<test_clock>(100u, opts, inserted_at, rng);

    static_cast<void>(next_refresh_point(sched)); // consume the one point
    auto result = next_refresh_point(sched);
    CHECK_FALSE(result.has_value());
}

TEST_CASE("jitter is deterministic with fixed RNG seed", "[ttl_refresh]")
{
    clock_guard cg;
    // Use non-zero jitter to verify determinism
    mdns_options opts{.refresh_jitter_pct = 0.02};
    auto inserted_at = test_clock::now();

    std::mt19937 rng1{1234};
    auto sched1 = make_refresh_schedule<test_clock>(100u, opts, inserted_at, rng1);

    std::mt19937 rng2{1234};
    auto sched2 = make_refresh_schedule<test_clock>(100u, opts, inserted_at, rng2);

    REQUIRE(sched1.fire_at.size() == sched2.fire_at.size());
    for(std::size_t i = 0; i < sched1.fire_at.size(); ++i)
        CHECK(sched1.fire_at[i] == sched2.fire_at[i]);
}

TEST_CASE("jitter is bounded within [0, wire_ttl * jitter_pct]", "[ttl_refresh]")
{
    clock_guard cg;
    mdns_options opts{
        .ttl_refresh_thresholds = {0.80},
        .refresh_jitter_pct     = 0.02,
    };
    auto inserted_at = test_clock::now();

    // Run many seeds to exercise the jitter bound
    for(uint32_t seed = 0; seed < 100; ++seed)
    {
        std::mt19937 rng{seed};
        auto sched = make_refresh_schedule<test_clock>(100u, opts, inserted_at, rng);

        REQUIRE(sched.fire_at.size() == 1);
        // Without jitter: 80000ms. Max jitter: 100 * 1000 * 0.02 = 2000ms
        auto offset = sched.fire_at[0] - inserted_at;
        CHECK(offset >= 80000ms);
        CHECK(offset <= 82000ms);
    }
}

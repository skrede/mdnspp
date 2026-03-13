#include "mdnspp/mdns_options.h"
#include "mdnspp/detail/query_backoff.h"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_floating_point.hpp>

#include <chrono>

using namespace mdnspp;
using namespace mdnspp::detail;
using namespace std::chrono_literals;

TEST_CASE("mdns_options default-constructs with RFC-compliant values", "[mdns_options]")
{
    mdns_options opts{};

    CHECK(opts.initial_interval == 1000ms);
    CHECK(opts.max_interval == std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::hours(1)));
    CHECK(opts.backoff_multiplier == 2.0);
    REQUIRE(opts.ttl_refresh_thresholds.size() == 4);
    CHECK(opts.ttl_refresh_thresholds[0] == 0.80);
    CHECK(opts.ttl_refresh_thresholds[1] == 0.85);
    CHECK(opts.ttl_refresh_thresholds[2] == 0.90);
    CHECK(opts.ttl_refresh_thresholds[3] == 0.95);
    CHECK(opts.refresh_jitter_pct == 0.02);
    CHECK(opts.tc_wait_min == 400ms);
    CHECK(opts.tc_wait_max == 500ms);
    CHECK(opts.max_known_answers == 0);
}

TEST_CASE("advance_backoff first call returns initial_interval", "[query_backoff]")
{
    mdns_options opts{};
    query_backoff_state state{};

    auto interval = advance_backoff(state, opts);

    CHECK(interval == 1000ms);
}

TEST_CASE("advance_backoff produces RFC default sequence", "[query_backoff]")
{
    // RFC 6762 section 5.2: 1s, 2s, 4s, 8s, ..., capped at 3600s
    mdns_options opts{};
    query_backoff_state state{};

    // Expected sequence (milliseconds): 1000, 2000, 4000, 8000, 16000, 32000,
    //   64000, 128000, 256000, 512000, 1024000, 2048000, 3600000, 3600000
    const std::vector<std::chrono::milliseconds> expected{
        1000ms, 2000ms, 4000ms, 8000ms, 16000ms, 32000ms,
        64000ms, 128000ms, 256000ms, 512000ms, 1024000ms, 2048000ms,
        3600000ms, 3600000ms
    };

    for(auto e : expected)
        CHECK(advance_backoff(state, opts) == e);
}

TEST_CASE("advance_backoff respects custom options", "[query_backoff]")
{
    // 500ms initial, 10s max, multiplier 3.0 -> 500ms, 1500ms, 4500ms, 10000ms, 10000ms
    mdns_options opts{
        .initial_interval = 500ms,
        .max_interval     = 10000ms,
        .backoff_multiplier = 3.0,
    };
    query_backoff_state state{};

    CHECK(advance_backoff(state, opts) == 500ms);
    CHECK(advance_backoff(state, opts) == 1500ms);
    CHECK(advance_backoff(state, opts) == 4500ms);
    CHECK(advance_backoff(state, opts) == 10000ms);
    CHECK(advance_backoff(state, opts) == 10000ms);
}

TEST_CASE("advance_backoff state can be reset by reconstructing", "[query_backoff]")
{
    mdns_options opts{};
    query_backoff_state state{};

    // Advance a few steps
    static_cast<void>(advance_backoff(state, opts)); // 1s
    static_cast<void>(advance_backoff(state, opts)); // 2s
    static_cast<void>(advance_backoff(state, opts)); // 4s

    // Reset by reconstructing
    state = query_backoff_state{};

    // Sequence should restart from initial_interval
    CHECK(advance_backoff(state, opts) == 1000ms);
    CHECK(advance_backoff(state, opts) == 2000ms);
}

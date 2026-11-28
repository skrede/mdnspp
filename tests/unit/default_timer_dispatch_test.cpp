#include "mdnspp/default/default_timer.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <thread>
#include <system_error>

using namespace std::chrono_literals;

TEST_CASE("a deadline beyond the int millisecond range yields a positive poll timeout", "[default_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    timer.expires_after(std::chrono::hours{24 * 30});
    timer.async_wait([](std::error_code) {});
    REQUIRE(ctx.compute_next_timeout_ms(std::chrono::steady_clock::now()) > 0);
    timer.cancel();
}

TEST_CASE("a timer destroyed by an earlier expired handler is not dispatched", "[default_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer first{ctx};
    auto second = std::make_unique<mdnspp::default_timer>(ctx);
    bool first_fired = false;
    bool second_fired = false;
    first.expires_after(-1ms);
    second->expires_after(-1ms);
    first.async_wait([&](std::error_code)
    {
        first_fired = true;
        second.reset();
    });
    second->async_wait([&](std::error_code) { second_fired = true; });
    ctx.poll_one();
    REQUIRE(first_fired);
    REQUIRE_FALSE(second_fired);
    REQUIRE(second == nullptr);
}

TEST_CASE("timers may be destroyed on another thread after the loop thread joins", "[default_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    timer.expires_after(1h);
    timer.async_wait([](std::error_code) {});
    std::thread worker{[&ctx] { ctx.poll_one(); }};
    worker.join();
    REQUIRE(timer.has_pending());
    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
}

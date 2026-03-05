// tests/native_timer_test.cpp

#include "mdnspp/policy.h"

#include "mdnspp/default/default_timer.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <system_error>

using namespace std::chrono_literals;

// static_assert compiled from native_timer.h — verified here as a belt-and-suspenders check.
static_assert(mdnspp::TimerLike<mdnspp::DefaultTimer>, "DefaultTimer must satisfy TimerLike");

TEST_CASE("DefaultTimer constructs from DefaultContext reference", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("DefaultTimer error_code constructor leaves ec unchanged", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    std::error_code ec{};
    mdnspp::DefaultTimer timer{ctx, ec};
    REQUIRE_FALSE(ec); // timer construction is infallible
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("DefaultTimer async_wait registers pending handler", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};
    bool called = false;
    timer.expires_after(1000ms);
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());
    REQUIRE_FALSE(called);
}

TEST_CASE("DefaultTimer expires_after drops pending handler WITHOUT calling it", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};
    bool called = false;

    timer.expires_after(1000ms);
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());

    // expires_after must drop the handler silently — critical recv_loop semantic.
    timer.expires_after(2000ms);
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(called); // handler was dropped, NOT called
}

TEST_CASE("DefaultTimer cancel fires handler with operation_canceled", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};
    std::error_code received{};

    timer.expires_after(1000ms);
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("DefaultTimer cancel with no pending handler is a no-op", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_NOTHROW(timer.cancel()); // must not crash or throw
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("DefaultTimer expires_after then async_wait re-arms correctly", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};
    int call_count = 0;

    timer.expires_after(1000ms);
    timer.async_wait([&](std::error_code) { ++call_count; });
    REQUIRE(timer.has_pending());

    // Re-arm: drops old handler without calling it.
    timer.expires_after(500ms);
    timer.async_wait([&](std::error_code) { ++call_count; });
    REQUIRE(timer.has_pending());
    REQUIRE(call_count == 0); // first handler was dropped, not called

    timer.cancel();
    REQUIRE(call_count == 1); // only the second handler was called
}

TEST_CASE("DefaultTimer fires when deadline has passed", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};
    std::error_code received{std::make_error_code(std::errc::interrupted)};

    // Set a deadline in the past.
    timer.expires_after(-1ms); // already expired
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    // fire_if_expired() should deliver success (no error).
    timer.fire_if_expired();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(received); // success error_code is falsy
}

TEST_CASE("DefaultTimer does not fire before deadline", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    mdnspp::DefaultTimer timer{ctx};
    bool called = false;

    timer.expires_after(60000ms); // 60 seconds in the future
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());

    timer.fire_if_expired();
    REQUIRE_FALSE(called);
    REQUIRE(timer.has_pending()); // still pending
}

TEST_CASE("DefaultTimer destructor deregisters from DefaultContext", "[native_timer]")
{
    mdnspp::DefaultContext ctx;
    {
        mdnspp::DefaultTimer timer{ctx};
        timer.expires_after(1000ms);
        timer.async_wait([](std::error_code)
        {
        });
        REQUIRE(timer.has_pending());
        // timer goes out of scope — must deregister without crashing
    }
    // ctx should not reference destroyed timer; poll_one is safe to call.
    REQUIRE_NOTHROW(ctx.poll_one());
}

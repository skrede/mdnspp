#include "mdnspp/policy.h"

#include "mdnspp/default/default_timer.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <system_error>

using namespace std::chrono_literals;

static_assert(mdnspp::timer_like<mdnspp::default_timer>, "default_timer must satisfy timer_like");

TEST_CASE("default_timer constructs from default_context reference", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("default_timer error_code constructor leaves ec unchanged", "[native_timer]")
{
    mdnspp::default_context ctx;
    std::error_code ec{};
    mdnspp::default_timer timer{ctx, ec};
    REQUIRE_FALSE(ec);
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("default_timer async_wait registers pending handler", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    bool called = false;
    timer.expires_after(1000ms);
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());
    REQUIRE_FALSE(called);
}

TEST_CASE("default_timer expires_after completes a pending handler with operation_canceled", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    std::error_code received{};

    timer.expires_after(1000ms);
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    timer.expires_after(2000ms);
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("default_timer cancel fires handler with operation_canceled", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    std::error_code received{};

    timer.expires_after(1000ms);
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("default_timer cancel with no pending handler is a no-op", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_NOTHROW(timer.cancel());
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("default_timer expires_after then async_wait re-arms correctly", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    int call_count = 0;

    timer.expires_after(1000ms);
    timer.async_wait([&](std::error_code) { ++call_count; });
    REQUIRE(timer.has_pending());

    timer.expires_after(500ms);
    timer.async_wait([&](std::error_code) { ++call_count; });
    REQUIRE(timer.has_pending());
    REQUIRE(call_count == 1);

    timer.cancel();
    REQUIRE(call_count == 2);
}

TEST_CASE("default_timer fires when deadline has passed", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    std::error_code received{std::make_error_code(std::errc::interrupted)};

    timer.expires_after(-1ms);
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    timer.fire_if_expired();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(received);
}

TEST_CASE("default_timer does not fire before deadline", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};
    bool called = false;

    timer.expires_after(60000ms);
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());

    timer.fire_if_expired();
    REQUIRE_FALSE(called);
    REQUIRE(timer.has_pending());
}

TEST_CASE("default_timer compute_next_timeout_ms returns -1 with no pending handlers", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

    timer.expires_after(100ms);
    REQUIRE_FALSE(timer.has_pending());

    const auto now = std::chrono::steady_clock::now();
    REQUIRE(ctx.compute_next_timeout_ms(now) == -1);
}

TEST_CASE("default_timer compute_next_timeout_ms clamps expired deadline to 0", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

    timer.expires_after(-1ms);
    timer.async_wait([](std::error_code) {});
    REQUIRE(timer.has_pending());

    const auto now = std::chrono::steady_clock::now();
    REQUIRE(ctx.compute_next_timeout_ms(now) == 0);

    timer.cancel();
}

TEST_CASE("default_timer fire_if_expired is a no-op when no handler is pending", "[native_timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

    timer.expires_after(-1ms);
    REQUIRE_FALSE(timer.has_pending());

    REQUIRE_NOTHROW(timer.fire_if_expired());
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("default_timer destructor deregisters from default_context", "[native_timer]")
{
    mdnspp::default_context ctx;
    {
        mdnspp::default_timer timer{ctx};
        timer.expires_after(1000ms);
        timer.async_wait([](std::error_code)
        {
        });
        REQUIRE(timer.has_pending());
    }
    REQUIRE_NOTHROW(ctx.poll_one());
}

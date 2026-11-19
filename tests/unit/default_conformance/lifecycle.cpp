#include "helpers.h"

#include "support/sync_wait.h"

#include <atomic>

TEST_CASE("default_context run/stop lifecycle", "[native][context]")
{
    mdnspp::default_context ctx;

    ctx.stop();
    ctx.run();

    ctx.restart();
    run_stopped_from_thread(ctx, 50ms);
    SUCCEED("default_context run/stop lifecycle works correctly");
}

TEST_CASE("default_context restart then run works after stop", "[native][context]")
{
    mdnspp::default_context ctx;

    ctx.stop();
    ctx.run();

    ctx.restart();
    run_stopped_from_thread(ctx, 30ms);

    ctx.restart();
    run_stopped_from_thread(ctx, 30ms);
    SUCCEED("restart/run/stop works across multiple cycles");
}

TEST_CASE("default_context poll_one returns immediately with no sockets", "[native][context]")
{
    mdnspp::default_context ctx;

    const auto start = std::chrono::steady_clock::now();
    ctx.poll_one();
    const auto elapsed = std::chrono::steady_clock::now() - start;

    REQUIRE(elapsed < 50ms);
}

TEST_CASE("default_context stop from another thread wakes run", "[native][context]")
{
    mdnspp::default_context ctx;
    std::atomic<bool> run_returned{false};

    std::thread runner{
        [&]
        {
            ctx.run();
            run_returned.store(true, std::memory_order_release);
        }
    };

    const bool running = mdnspp::test_support::round_trip([&ctx](auto marker) { ctx.post(std::move(marker)); }, 5s);
    const bool returned_early = run_returned.load(std::memory_order_acquire);

    ctx.stop();
    runner.join();

    REQUIRE(running);
    REQUIRE_FALSE(returned_early);
    REQUIRE(run_returned.load(std::memory_order_acquire));
}

TEST_CASE("default_timer expires_after drops pending handler", "[native][timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

    bool called = false;
    timer.async_wait([&](std::error_code) { called = true; });
    REQUIRE(timer.has_pending());

    timer.expires_after(100ms);
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE_FALSE(called);
}

TEST_CASE("default_timer cancel delivers operation_canceled", "[native][timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

    std::error_code received{};
    timer.async_wait([&](std::error_code ec) { received = ec; });
    REQUIRE(timer.has_pending());

    timer.cancel();
    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(received == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("default_timer fires after deadline via run()", "[native][timer]")
{
    mdnspp::default_context ctx;
    mdnspp::default_timer timer{ctx};

    bool fired = false;
    std::error_code ec_received{std::make_error_code(std::errc::interrupted)};

    timer.expires_after(10ms);
    timer.async_wait([&](std::error_code ec)
    {
        fired = true;
        ec_received = ec;
    });

    while(!fired)
    {
        ctx.poll_one();
        std::this_thread::sleep_for(1ms);
    }

    REQUIRE(fired);
    REQUIRE_FALSE(ec_received);
}

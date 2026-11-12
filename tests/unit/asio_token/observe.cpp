#include "helpers.h"

TEST_CASE_METHOD(observer_fixture, "async_observe with callback fires when stop() is called",
                 "[completion_token][callback][observer]")
{
    bool handler_fired = false;
    obs->async_observe([&handler_fired](std::error_code) { handler_fired = true; });

    run_and_stop_after(50ms);

    REQUIRE(handler_fired);
}

TEST_CASE_METHOD(observer_fixture, "async_observe completion handler dispatched on correct executor -- TSan clean",
                 "[completion_token][tsan][observer]")
{
    bool handler_fired = false;
    obs->async_observe([&handler_fired](std::error_code) { handler_fired = true; });

    run_and_stop_after(50ms);

    REQUIRE(handler_fired);
}

TEST_CASE_METHOD(observer_fixture, "async_observe with cancel_after completes with operation_canceled",
                 "[completion_token][cancellation][cancel_after][observer]")
{
    auto fut = mdnspp::async_observe(*obs, asio::cancel_after(100ms, asio::as_tuple(asio::use_future)));

    io.run();

    auto [ec] = fut.get();
    REQUIRE(ec == std::errc::operation_canceled);
}

#ifdef ASIO_HAS_CO_AWAIT

TEST_CASE_METHOD(observer_fixture, "async_observe with use_awaitable suspends until stop",
                 "[completion_token][use_awaitable][observer]")
{
    asio::steady_timer stop_timer{io, 100ms};
    stop_timer.async_wait([obs = obs](std::error_code) { obs->stop(); });

    bool completed = false;
    std::error_code completion_ec;
    asio::co_spawn(
        io,
        [this, &completed, &completion_ec]() -> asio::awaitable<void>
        {
            auto [ec] = co_await mdnspp::async_observe(*obs, asio::as_tuple(asio::use_awaitable));
            completion_ec = ec;
            completed = true;
            io.stop();
        },
        asio::detached);

    io.run_for(5s);
    REQUIRE(completed);
    REQUIRE(completion_ec == std::errc::operation_canceled);
}

// operator|| cancels the loser through its cancellation slot; without slot support the
// observe arm never completes and the co_await suspends forever.
TEST_CASE_METHOD(observer_fixture, "async_observe loses an awaitable || race and is cancelled by the group",
                 "[completion_token][cancellation][use_awaitable][observer]")
{
    bool timer_won = false;
    asio::co_spawn(
        io,
        [this, &timer_won]() -> asio::awaitable<void>
        {
            using namespace asio::experimental::awaitable_operators;
            asio::steady_timer deadline{io, 100ms};
            auto winner = co_await (mdnspp::async_observe(*obs, asio::use_awaitable)
                                    || deadline.async_wait(asio::use_awaitable));
            timer_won = winner.index() == 1;
            io.stop();
        },
        asio::detached);

    io.run_for(5s);
    REQUIRE(timer_won);
}

#endif

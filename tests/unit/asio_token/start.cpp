#include "helpers.h"

TEST_CASE_METHOD(server_fixture, "async_start adapter completes with operation_canceled when stop() precedes ready",
                 "[completion_token][callback][service_server]")
{
    create(make_info("Test", "testhost", 8080, "192.168.1.10"));

    completion_probe start;
    mdnspp::async_start(*server, start.handler());

    run_io();
    std::this_thread::sleep_for(50ms);
    // The default probe schedule needs about 750 ms, so the server is not yet live.
    stop_and_join();

    REQUIRE(start.fired());
    REQUIRE(start.ec == std::errc::operation_canceled);
}

TEST_CASE_METHOD(server_fixture, "async_start adapter completes at ready without stop()",
                 "[completion_token][use_future][service_server][ready]")
{
    create(make_info("TestReady", "testready", 8081, "192.168.1.11"), fast_service_options());

    auto fut = mdnspp::async_start(*server, asio::use_future);
    run_io();

    REQUIRE(fut.wait_for(5s) == std::future_status::ready);
    REQUIRE_NOTHROW(fut.get());

    stop_and_join();
}

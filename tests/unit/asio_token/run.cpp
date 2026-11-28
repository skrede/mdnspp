#include "helpers.h"

TEST_CASE_METHOD(server_fixture, "async_run completes only after stop() runs the teardown",
                 "[completion_token][callback][service_server][run]")
{
    create(make_info("TestRun", "testrun", 8082, "192.168.1.12"), fast_service_options());

    completion_probe run{std::make_error_code(std::errc::io_error)};
    mdnspp::async_run(*server, run.handler());
    run_io();

    sync_io();
    REQUIRE_FALSE(run.fired());

    stop_and_join();

    REQUIRE(run.fired());
    REQUIRE(run.ec == std::error_code{});
}

TEST_CASE_METHOD(server_fixture, "async_run after stop() completes deterministically with invalid_argument",
                 "[completion_token][callback][service_server][run][misuse]")
{
    create(make_info("TestRunMisuse", "testrunmisuse", 8083, "192.168.1.13"));
    server->stop();

    completion_probe run;
    mdnspp::async_run(*server, run.handler());

    io.run();
    server.reset();

    REQUIRE(run.fired());
    REQUIRE(run.ec == std::errc::invalid_argument);
}

// The misuse completion is posted: the second token completes with operation_in_progress
// while the first operation keeps running until stop().
TEST_CASE_METHOD(server_fixture, "second async_run completes with operation_in_progress while the first keeps running",
                 "[completion_token][callback][service_server][run][misuse]")
{
    create(make_info("TestRunDouble", "testrundouble", 8084, "192.168.1.14"), fast_service_options());

    completion_probe first{std::make_error_code(std::errc::io_error)};
    completion_probe second;
    mdnspp::async_run(*server, first.handler());
    mdnspp::async_run(*server, second.handler());
    run_io();

    REQUIRE(mdnspp::test_support::wait_until([&second] { return second.fired(); }, 5s));
    sync_io();
    REQUIRE(second.count.load() == 1);
    REQUIRE(second.ec == std::errc::operation_in_progress);
    REQUIRE(first.count.load() == 0);

    stop_and_join();

    REQUIRE(first.count.load() == 1);
    REQUIRE(first.ec == std::error_code{});
    REQUIRE(second.count.load() == 1);
}

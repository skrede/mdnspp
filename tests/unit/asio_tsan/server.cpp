#include "helpers.h"

TEST_CASE_METHOD(tsan_fixture, "service_server stop() from separate thread is data-race-free",
                 "[service_server][tsan][asio]")
{
    create(make_tsan_info());
    server->async_start();
    run_io();

    std::this_thread::sleep_for(50ms);
    server->stop();

    join_and_reset();
    REQUIRE(true);
}

TEST_CASE_METHOD(tsan_fixture, "service_server double stop is safe under concurrency",
                 "[service_server][tsan][asio]")
{
    create(make_tsan_info());
    server->async_start();
    run_io();
    std::this_thread::sleep_for(50ms);

    std::thread stop_thread([this] { server->stop(); });
    server->stop();

    stop_thread.join();
    join_and_reset();
    REQUIRE(true);
}

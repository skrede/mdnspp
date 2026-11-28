#include "helpers.h"

namespace {

constexpr std::string_view instance = "TSanServer";

void check_completed_once(const tsan_fixture &f)
{
    CHECK(f.ready.calls == 1);
    CHECK((!f.ready.ec || f.ready.ec == std::errc::operation_canceled));
    CHECK(f.done.calls == 1);
    CHECK_FALSE(f.done.ec);
}

}

TEST_CASE_METHOD(tsan_fixture, "service_server stop() from separate thread is data-race-free",
                 "[service_server][tsan][asio]")
{
    create(make_tsan_info(instance));
    start_logged();

    sync_io();
    server->stop();

    join_and_reset();
    check_completed_once(*this);
}

TEST_CASE_METHOD(tsan_fixture, "service_server double stop is safe under concurrency",
                 "[service_server][tsan][asio]")
{
    create(make_tsan_info(instance));
    start_logged();
    sync_io();

    std::thread stop_thread([this] { server->stop(); });
    server->stop();

    stop_thread.join();
    join_and_reset();
    check_completed_once(*this);
}

#include "helpers.h"

TEST_CASE_METHOD(tsan_fixture, "concurrent update_service_info is TSan-clean", "[service_server][tsan][asio][update]")
{
    create(make_tsan_info());
    server->async_start();

    std::thread update_thread([this]
    {
        for(int32_t i = 0; i < 10; ++i)
        {
            auto info = make_tsan_info();
            info.port = static_cast<uint16_t>(9000 + i);
            server->update_service_info(std::move(info));
        }
    });

    asio::steady_timer deadline(io, 200ms);
    deadline.async_wait([this](std::error_code) { server->stop(); });
    io.run();

    update_thread.join();
    server.reset();
    REQUIRE(true);
}

TEST_CASE_METHOD(tsan_fixture, "stop() from a non-executor thread racing update_service_info is TSan-clean",
                 "[service_server][tsan][asio][update][stop]")
{
    create(make_tsan_info(), fast_service_options());
    start_and_wait_live();

    // Each update assigns m_info on the executor regardless of content. The content stays
    // identical so looped-back announcements never differ from the live record set; a changed
    // rdata would be treated as a conflict and abort the server mid-test.
    std::thread update_thread([this]
    {
        for(int32_t i = 0; i < 100; ++i)
            server->update_service_info(make_tsan_info());
    });
    update_thread.join();

    // stop() must not read m_info on this thread: the goodbye is built and sent inside the posted teardown.
    server->stop();

    join_and_reset();
    REQUIRE(true);
}

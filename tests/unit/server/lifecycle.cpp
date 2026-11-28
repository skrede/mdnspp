#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <string_view>
#include <system_error>

namespace {

void misuse_sections(server_fixture &f, std::errc expected, std::string_view completes_with)
{
    THEN("the misuse completion is posted, not invoked inline")
    {
        REQUIRE_FALSE(f.ready.fired);
    }

    THEN(completes_with)
    {
        f.ex.drain_posted();
        check_failed_with(f.ready, expected);
    }
}

}

SCENARIO("async_start and stop lifecycle", "[service_server][lifecycle]")
{
    GIVEN("a service_server with no enqueued queries")
    {
        server_fixture f;

        WHEN("async_start() is called")
        {
            f.start();

            THEN("stop() can be called without error")
            {
                REQUIRE_NOTHROW(f.server.stop());

                AND_THEN("stop() can be called again (idempotent)")
                {
                    REQUIRE_NOTHROW(f.server.stop());
                }
            }
        }
    }
}

SCENARIO("async_start fires completion callback on stop", "[service_server][async]")
{
    GIVEN("a service_server with no enqueued queries")
    {
        server_fixture f;

        WHEN("async_start() is called with on_done completion callback")
        {
            f.start({}, record_into(f.done));

            AND_WHEN("stop() is called")
            {
                f.stop();

                THEN("the on_done callback fires with error_code{}")
                {
                    check_succeeded(f.done);
                }
            }
        }
    }
}

SCENARIO("async_start completion handler fires exactly once on double stop",
         "[service_server][stop-idempotent][completion]")
{
    GIVEN("a started service_server with on_done callback")
    {
        server_fixture f;
        f.start({}, record_into(f.done));
        advance_to_live(f.server);

        WHEN("stop() is called twice")
        {
            f.server.stop();
            f.server.stop();
            f.ex.drain_posted();

            THEN("the on_done callback fires exactly once")
            {
                REQUIRE(f.done.calls == 1);
            }
        }
    }
}

SCENARIO("stop before timer fires prevents response", "[service_server][stop][cancel]")
{
    GIVEN("a service_server that has been started")
    {
        server_fixture f;

        WHEN("async_start() is called then stop() is called during probing")
        {
            f.start();
            f.server.stop();

            AND_WHEN("timer().fire() is called (simulating a late fire after cancel)")
            {
                f.fire();

                THEN("no response or announcement is sent after stop")
                {
                    auto sent_before = f.sent().size();
                    f.fire();
                    REQUIRE(f.sent().size() == sent_before);
                }
            }
        }
    }
}

SCENARIO("async_start is one-shot", "[service_server][one-shot]")
{
    GIVEN("a started service_server")
    {
        server_fixture f;
        f.start();

        WHEN("async_start is called a second time")
        {
            f.server.async_start(record_into(f.ready));
            misuse_sections(f, std::errc::operation_in_progress, "on_ready completes with operation_in_progress");
        }

        WHEN("async_start is called after stop()")
        {
            f.stop();
            f.server.async_start(record_into(f.ready));
            misuse_sections(f, std::errc::invalid_argument, "on_ready completes with invalid_argument");
        }
    }
}

SCENARIO("stop discards pending posted work", "[service_server][update][stop]")
{
    GIVEN("a live service_server with posted update_service_info")
    {
        // Without the goodbye, any packet the drained teardown sends is a wrongly executed announcement.
        server_fixture f{make_test_info(), service_options{.send_goodbye = false}};
        f.go_live();
        f.server.update_service_info(make_test_info());

        WHEN("stop() is called then posted work is drained")
        {
            f.server.stop();
            f.clear_sent();
            f.ex.drain_posted();

            THEN("no announcement was sent after stop")
            {
                REQUIRE(f.sent().empty());
            }
        }
    }
}

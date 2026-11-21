#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <system_error>

namespace {

void destroy_while_pending(mock_executor &ex, completion &ready, completion &done)
{
    basic_service_server<mock_policy> server{ex, make_test_info()};
    server.async_start(record_into(ready), record_into(done));
}

void destroy_after_stop(mock_executor &ex, completion &ready, completion &done)
{
    basic_service_server<mock_policy> server{ex, make_test_info()};
    server.async_start(record_into(ready), record_into(done));
    server.stop();
    ex.drain_posted();
}

void canceled_once_sections(mock_executor &ex, const completion &ready, const completion &done)
{
    THEN("on_ready fired exactly once with operation_canceled")
    {
        REQUIRE(ready.calls == 1);
        REQUIRE(ready.ec == std::errc::operation_canceled);
    }

    THEN("on_done fired exactly once with operation_canceled")
    {
        REQUIRE(done.calls == 1);
        REQUIRE(done.ec == std::errc::operation_canceled);
    }

    THEN("draining the dropped teardown does not complete them again")
    {
        REQUIRE_NOTHROW(ex.drain_posted());
        REQUIRE(ready.calls == 1);
        REQUIRE(done.calls == 1);
    }
}

void completed_once_sections(const completion &ready, const completion &done)
{
    THEN("destruction does not complete the handlers a second time")
    {
        REQUIRE(ready.calls == 1);
        REQUIRE(ready.ec == std::errc::operation_canceled);
        REQUIRE(done.calls == 1);
        REQUIRE(done.ec == std::error_code{});
    }
}

}

SCENARIO("destruction completes pending handlers exactly once with operation_canceled",
         "[service_server][destructor][completion]")
{
    GIVEN("a mock_executor outliving the server")
    {
        mock_executor ex;
        completion ready;
        completion done;

        WHEN("a server is destroyed while async_start is still pending")
        {
            destroy_while_pending(ex, ready, done);
            canceled_once_sections(ex, ready, done);
        }

        WHEN("stop() completed the handlers before destruction")
        {
            destroy_after_stop(ex, ready, done);
            completed_once_sections(ready, done);
        }
    }
}

SCENARIO("liveness guard prevents use-after-free on server destruction", "[service_server][update][liveness]")
{
    GIVEN("a mock_executor outliving the server")
    {
        mock_executor ex;

        WHEN("a server posts update_service_info() then is destroyed before drain")
        {
            {
                basic_service_server<mock_policy> server{ex, make_test_info()};
                server.async_start();
                advance_to_live(server);
                server.update_service_info(make_test_info());
            }

            THEN("draining posted work does not crash (liveness guard skips)")
            {
                REQUIRE_NOTHROW(ex.drain_posted());
            }
        }
    }
}

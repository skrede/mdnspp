#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <system_error>

namespace {

querier_completion_handler record_empty_into(query_outcome &out)
{
    return [&out](std::error_code ec, std::vector<mdns_record_variant> results)
    {
        out.fired = true;
        out.ec = ec;
        REQUIRE(results.empty());
    };
}

}

SCENARIO("stop() before natural completion fires with operation_canceled", "[querier][stop][cancel]")
{
    GIVEN("a querier with one accumulated result and the silence timer pending")
    {
        querier_fixture f;
        f.enqueue(make_a_response("myhost.local.", 192, 168, 1, 1));
        f.query(record_into(f.done));

        WHEN("stop() is called before the silence timer fires")
        {
            f.q.stop();
            f.ex.drain_posted();

            THEN("the completion fires with operation_canceled and the partial results")
            {
                REQUIRE(f.done.fired);
                REQUIRE(f.done.ec == std::errc::operation_canceled);
                REQUIRE(f.done.results.size() == 1);
            }
        }
    }
}

SCENARIO("destruction with a pending query completes the handler with operation_canceled", "[querier][destructor]")
{
    GIVEN("a started querier whose silence timer never fires")
    {
        mock_executor ex;
        query_outcome done;
        {
            basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};
            q.async_query("myhost.local.", dns_type::a, record_into(done));
        }

        THEN("the completion handler fired with operation_canceled")
        {
            REQUIRE(done.fired);
            REQUIRE(done.ec == std::errc::operation_canceled);
        }
    }
}

SCENARIO("second async_query completes with operation_in_progress", "[querier][one-shot]")
{
    GIVEN("a querier with a query in flight")
    {
        querier_fixture f;
        f.query();

        WHEN("async_query() is called a second time")
        {
            f.query(record_empty_into(f.done), "other.local.");
            f.ex.drain_posted();

            THEN("the second handler fires with operation_in_progress")
            {
                REQUIRE(f.done.fired);
                REQUIRE(f.done.ec == std::errc::operation_in_progress);
            }
        }
    }
}

SCENARIO("async_query after stop completes with invalid_argument", "[querier][one-shot]")
{
    GIVEN("a querier that was stopped before ever starting")
    {
        querier_fixture f;
        f.q.stop();

        WHEN("async_query() is called")
        {
            f.query(record_into(f.done));
            f.ex.drain_posted();

            THEN("the handler fires with invalid_argument")
            {
                REQUIRE(f.done.fired);
                REQUIRE(f.done.ec == std::errc::invalid_argument);
            }
        }
    }
}

SCENARIO("querier stop without starting does not crash", "[querier][stop][no-start]")
{
    GIVEN("a querier constructed but never started")
    {
        querier_fixture f;

        WHEN("stop() is called")
        {
            THEN("no crash or handler fire occurs")
            {
                REQUIRE_NOTHROW(f.q.stop());
            }
        }
    }
}

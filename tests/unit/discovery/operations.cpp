#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <variant>
#include <system_error>

namespace {

browse_completion_handler record_empty_into(browse_outcome &out)
{
    return [&out](std::error_code ec, std::vector<resolved_service> svcs)
    {
        out.fired = true;
        out.ec = ec;
        REQUIRE(svcs.empty());
    };
}

record_callback capture_into(std::vector<mdns_record_variant> &records)
{
    return [&records](const endpoint &, const mdns_record_variant &rec) { records.push_back(rec); };
}

void second_operation_sections(discovery_fixture &f)
{
    WHEN("async_browse() is called while discover is running")
    {
        f.browse(record_empty_into(f.browsed));
        f.ex.drain_posted();

        THEN("the browse handler fires with operation_in_progress")
        {
            check_completed_with(f.browsed, std::errc::operation_in_progress);
        }
    }

    WHEN("async_discover() is called a second time")
    {
        f.discover(record_into(f.found), "_ftp._tcp.local.");
        f.ex.drain_posted();

        THEN("the second handler fires with operation_in_progress")
        {
            check_completed_with(f.found, std::errc::operation_in_progress);
        }
    }
}

}

SCENARIO("operations on one service_discovery are mutually exclusive", "[service_discovery][one-shot]")
{
    GIVEN("a service_discovery with a discover in flight")
    {
        discovery_fixture f;
        f.discover();
        second_operation_sections(f);
    }

    GIVEN("a service_discovery stopped before ever starting")
    {
        discovery_fixture f;
        f.sd.stop();

        WHEN("async_discover() is called")
        {
            f.discover(record_into(f.found));
            f.ex.drain_posted();

            THEN("the handler fires with invalid_argument")
            {
                check_completed_with(f.found, std::errc::invalid_argument);
            }
        }
    }
}

SCENARIO("service_discovery stop with both discover and browse loops", "[service_discovery][stop][browse]")
{
    GIVEN("a service_discovery with browse started and a PTR response queued")
    {
        discovery_fixture f;
        f.enqueue(make_ptr_response("_http._tcp.local.", "Svc._http._tcp.local."));
        f.browse(record_into(f.browsed));

        WHEN("stop() is called")
        {
            f.stop();

            THEN("the browse completion fires with aggregated results")
            {
                REQUIRE(f.browsed.fired);
                REQUIRE(f.browsed.results.size() == 1);
            }
        }
    }
}

SCENARIO("stop() during async_browse fires completion with partial aggregated results", "[service_discovery][browse][stop]")
{
    GIVEN("a service_discovery with a PTR-only response and no silence timeout fired")
    {
        discovery_fixture f;
        f.enqueue(make_ptr_response("_http._tcp.local.", "StoppedService._http._tcp.local."));
        f.browse(record_into(f.browsed));

        WHEN("stop() is called before the silence timeout")
        {
            f.stop();

            THEN("browse completion fires with whatever was aggregated so far")
            {
                REQUIRE(f.browsed.fired);
                REQUIRE(f.browsed.results.size() == 1);
                REQUIRE(f.browsed.results[0].instance_name == "StoppedService._http._tcp.local");
            }
        }
    }
}

SCENARIO("on_record callback fires during async_browse (same as async_discover)", "[service_discovery][browse][on_record]")
{
    GIVEN("a service_discovery with an on_record callback and a PTR response")
    {
        mock_executor ex;
        std::vector<mdns_record_variant> captured_records;
        basic_service_discovery<mock_policy> sd{
            ex, query_options{.on_record = capture_into(captured_records), .silence_timeout = 500ms}};
        sd.socket().enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("async_browse() is called and silence timer fires")
        {
            sd.async_browse("_http._tcp.local.", ignore_browse());
            sd.timer().fire();

            THEN("on_record callback was invoked for each relevant record")
            {
                REQUIRE(captured_records.size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(captured_records[0]));
            }
        }
    }
}

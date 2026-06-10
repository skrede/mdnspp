#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO("service_discovery non-throwing constructor sets ec on success", "[service_discovery][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_service_discovery<mock_policy> is constructed with the ec overload")
        {
            basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}, {}, {}, ec};

            THEN("ec is clear and the service_discovery is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}

SCENARIO("service_discovery is move-constructible before async_discover", "[service_discovery][move]")
{
    GIVEN("a service_discovery constructed but not started")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};

        WHEN("move-constructed into a new instance")
        {
            basic_service_discovery<mock_policy> moved{std::move(sd)};

            THEN("the moved-to instance is usable")
            {
                REQUIRE(moved.socket().queue_empty());
                REQUIRE(moved.results().empty());
            }
        }
    }
}

SCENARIO("service_discovery stop with both discover and browse loops", "[service_discovery][stop][browse]")
{
    GIVEN("a service_discovery with browse started and a PTR response queued")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};

        sd.socket().enqueue(make_ptr_response(
            "_http._tcp.local.",
            "Svc._http._tcp.local."));

        std::vector<resolved_service> received_services;
        bool browse_fired = false;

        sd.async_browse("_http._tcp.local.",
                        [&](std::error_code, std::vector<resolved_service> svcs)
                        {
                            browse_fired = true;
                            received_services = std::move(svcs);
                        });

        WHEN("stop() is called")
        {
            sd.stop();
            ex.drain_posted();

            THEN("the browse completion fires with aggregated results")
            {
                REQUIRE(browse_fired);
                REQUIRE(received_services.size() == 1);
            }
        }
    }
}

SCENARIO("stop() during async_browse fires completion with partial aggregated results", "[service_discovery][browse][stop]")
{
    GIVEN("a service_discovery with a PTR-only response and no silence timeout fired")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};

        sd.socket().enqueue(make_ptr_response(
            "_http._tcp.local.",
            "StoppedService._http._tcp.local."));

        std::vector<resolved_service> received_services;
        bool callback_fired = false;

        sd.async_browse("_http._tcp.local.",
                        [&](std::error_code, std::vector<resolved_service> svcs)
                        {
                            callback_fired = true;
                            received_services = std::move(svcs);
                        });

        WHEN("stop() is called before the silence timeout")
        {
            sd.stop();
            ex.drain_posted();

            THEN("browse completion fires with whatever was aggregated so far")
            {
                REQUIRE(callback_fired);
                REQUIRE(received_services.size() == 1);
                REQUIRE(received_services[0].instance_name == "StoppedService._http._tcp.local");
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
            ex,
            query_options{
                .on_record = [&](const endpoint &, const mdns_record_variant &rec)
                {
                    captured_records.push_back(rec);
                },
                .silence_timeout = 500ms
            }
        };

        sd.socket().enqueue(make_ptr_response(
            "_http._tcp.local.",
            "MyService._http._tcp.local."));

        WHEN("async_browse() is called and silence timer fires")
        {
            sd.async_browse("_http._tcp.local.",
                            [](std::error_code, std::vector<resolved_service>)
                            {
                            });

            sd.timer().fire();

            THEN("on_record callback was invoked for each relevant record")
            {
                REQUIRE(captured_records.size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(captured_records[0]));
            }
        }
    }
}

SCENARIO("basic_service_discovery with socket_options", "[service_discovery][socket_options]")
{
    GIVEN("a socket_options with a specific interface address")
    {
        mock_executor ex;
        socket_options opts{.interface_address = "172.16.0.1"};

        WHEN("basic_service_discovery<mock_policy> is constructed with socket_options")
        {
            basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}, opts};

            THEN("the socket stores the options")
            {
                REQUIRE(sd.socket().options().interface_address == "172.16.0.1");
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}

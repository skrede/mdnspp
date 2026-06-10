#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <type_traits>
#include <system_error>

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

SCENARIO("service_discovery is neither copyable nor movable", "[service_discovery][move]")
{
    STATIC_REQUIRE_FALSE(std::is_copy_constructible_v<basic_service_discovery<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_copy_assignable_v<basic_service_discovery<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_move_constructible_v<basic_service_discovery<mock_policy>>);
    STATIC_REQUIRE_FALSE(std::is_move_assignable_v<basic_service_discovery<mock_policy>>);
}

SCENARIO("stop() vs natural completion error codes", "[service_discovery][stop][cancel]")
{
    GIVEN("a service_discovery with a PTR response enqueued")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};
        sd.socket().enqueue(make_ptr_response("_http._tcp.local.", "Svc._http._tcp.local."));

        std::error_code received_ec;
        bool callback_fired = false;

        sd.async_discover("_http._tcp.local.",
                          [&](std::error_code ec, std::vector<mdns_record_variant>)
                          {
                              callback_fired = true;
                              received_ec = ec;
                          });

        WHEN("the silence timer fires (natural completion)")
        {
            sd.timer().fire();

            THEN("the completion fires with success")
            {
                REQUIRE(callback_fired);
                REQUIRE_FALSE(received_ec);
            }
        }

        WHEN("stop() is called before the silence timeout")
        {
            sd.stop();
            ex.drain_posted();

            THEN("the completion fires with operation_canceled")
            {
                REQUIRE(callback_fired);
                REQUIRE(received_ec == std::errc::operation_canceled);
            }
        }
    }
}

SCENARIO("destruction with a pending discover completes the handler with operation_canceled", "[service_discovery][destructor]")
{
    GIVEN("a started discovery that is destroyed without completing")
    {
        mock_executor ex;
        std::error_code received_ec;
        bool callback_fired = false;

        {
            basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};
            sd.async_discover("_http._tcp.local.",
                              [&](std::error_code ec, std::vector<mdns_record_variant>)
                              {
                                  callback_fired = true;
                                  received_ec = ec;
                              });
        } // destroyed with the operation pending

        THEN("the completion handler fired with operation_canceled")
        {
            REQUIRE(callback_fired);
            REQUIRE(received_ec == std::errc::operation_canceled);
        }
    }
}

SCENARIO("operations on one service_discovery are mutually exclusive", "[service_discovery][one-shot]")
{
    GIVEN("a service_discovery with a discover in flight")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};

        sd.async_discover("_http._tcp.local.",
                          [](std::error_code, std::vector<mdns_record_variant>)
                          {
                          });

        WHEN("async_browse() is called while discover is running")
        {
            std::error_code received_ec;
            bool callback_fired = false;

            sd.async_browse("_http._tcp.local.",
                            [&](std::error_code ec, std::vector<resolved_service> svcs)
                            {
                                callback_fired = true;
                                received_ec = ec;
                                REQUIRE(svcs.empty());
                            });
            ex.drain_posted();

            THEN("the browse handler fires with operation_in_progress")
            {
                REQUIRE(callback_fired);
                REQUIRE(received_ec == std::errc::operation_in_progress);
            }
        }

        WHEN("async_discover() is called a second time")
        {
            std::error_code received_ec;
            bool callback_fired = false;

            sd.async_discover("_ftp._tcp.local.",
                              [&](std::error_code ec, std::vector<mdns_record_variant>)
                              {
                                  callback_fired = true;
                                  received_ec = ec;
                              });
            ex.drain_posted();

            THEN("the second handler fires with operation_in_progress")
            {
                REQUIRE(callback_fired);
                REQUIRE(received_ec == std::errc::operation_in_progress);
            }
        }
    }

    GIVEN("a service_discovery stopped before ever starting")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};
        sd.stop();

        WHEN("async_discover() is called")
        {
            std::error_code received_ec;
            bool callback_fired = false;

            sd.async_discover("_http._tcp.local.",
                              [&](std::error_code ec, std::vector<mdns_record_variant>)
                              {
                                  callback_fired = true;
                                  received_ec = ec;
                              });
            ex.drain_posted();

            THEN("the handler fires with invalid_argument")
            {
                REQUIRE(callback_fired);
                REQUIRE(received_ec == std::errc::invalid_argument);
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

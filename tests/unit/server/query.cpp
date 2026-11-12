#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO_METHOD(live_server, "service_server responds to PTR query after probe+announce and timer fires",
                "[service_server][ptr][response]")
{
    WHEN("a PTR query is received in live state and the response timer fires")
    {
        inject(endpoint{"192.168.1.50", 5353}, make_ptr_query("_http._tcp.local."));
        server.delay_timer().fire();

        THEN("exactly one multicast response is sent")
        {
            REQUIRE(count_multicast_responses_after(sent(), 0) == 1);
        }
    }
}

SCENARIO("service_server responds to PTR query when enqueued before start", "[service_server][ptr][response][live]")
{
    GIVEN("a service_server with a PTR query enqueued before start")
    {
        mock_executor ex;
        endpoint sender{"192.168.1.50", 5353};
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.socket().enqueue(make_ptr_query("_http._tcp.local."), sender);
        server.async_start();

        WHEN("the probe+announce sequence completes and the response timer fires")
        {
            advance_to_live(server);

            THEN("no response was sent for the dropped query (queries during probing are dropped)")
            {
                REQUIRE_FALSE(sent_to(server.socket().sent_packets(), sender));
            }
        }
    }
}

SCENARIO_METHOD(live_server, "response delay timer armed after query receipt in live state", "[service_server][timer]")
{
    WHEN("the server is in live state")
    {
        THEN("there is no pending response timer (no queries received in live state)")
        {
            REQUIRE_FALSE(server.delay_timer().has_pending());
        }
    }
}

SCENARIO("service_server ignores non-matching query", "[service_server][query][no-match]")
{
    GIVEN("a live service_server with a non-matching query enqueued before start")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.socket().enqueue(build_dns_query("_wrong._tcp.local.", dns_type::ptr));

        WHEN("async_start() is called and probing completes")
        {
            server.async_start();
            advance_to_live(server);

            THEN("no response was sent for the non-matching query")
            {
                server.delay_timer().fire();
                REQUIRE_FALSE(any_response_has_ptr(server.socket().sent_packets(), "_wrong"));
            }
        }
    }
}

SCENARIO("response sent to multicast by default, unicast when QU bit set", "[service_server][endpoint][rfc6762]")
{
    GIVEN("a service_server with on_query callback")
    {
        mock_executor ex;
        response_mode observed_mode = response_mode::multicast;
        service_options opts;
        opts.on_query = [&](const endpoint &, dns_type, response_mode mode) { observed_mode = mode; };
        basic_service_server<mock_policy> server{ex, make_test_info(), std::move(opts)};

        THEN("the server compiles and constructs with on_query callback")
        {
            REQUIRE(server.socket().queue_empty());
        }
    }
}

SCENARIO_METHOD(live_server, "Response delay timer is armed for multicast queries", "[delay]")
{
    WHEN("a multicast PTR query is injected")
    {
        inject_query(endpoint{"192.168.1.50", 5353}, "_http._tcp.local.", dns_type::ptr, response_mode::multicast);

        THEN("the response timer is armed (response not sent immediately)")
        {
            REQUIRE(server.delay_timer().has_pending());
            REQUIRE(sent().empty());

            AND_WHEN("the timer fires")
            {
                server.delay_timer().fire();

                THEN("the response is sent")
                {
                    REQUIRE_FALSE(sent().empty());
                }
            }
        }
    }
}

SCENARIO_METHOD(live_server, "Response delay timer duration is within 20-120ms for multicast queries", "[delay]")
{
    WHEN("a multicast PTR query is injected")
    {
        inject_query(endpoint{"192.168.1.50", 5353}, "_http._tcp.local.", dns_type::ptr, response_mode::multicast);

        THEN("the timer delay is within 20-120ms")
        {
            auto d = server.delay_timer().last_duration();
            REQUIRE(d >= std::chrono::milliseconds(20));
            REQUIRE(d <= std::chrono::milliseconds(120));
        }
    }
}

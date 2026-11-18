#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO_METHOD(live_server, "New queries merge into pending response", "[aggregation]")
{
    WHEN("a PTR query is injected, then an SRV query before the timer fires")
    {
        endpoint sender{"192.168.1.50", 5353};
        inject_query(sender, "_http._tcp.local.", dns_type::ptr, response_mode::multicast);
        inject_query(sender, "MyService._http._tcp.local.", dns_type::srv, response_mode::multicast);
        server.delay_timer().fire();

        THEN("exactly one multicast response is sent containing both PTR and SRV")
        {
            REQUIRE(count_multicast_responses_after(sent(), 0) == 1);
            REQUIRE(response_has<record_ptr>(last_data()));
            REQUIRE(response_has<record_srv>(last_data()));
        }
    }
}

SCENARIO_METHOD(live_server, "Subsequent queries do not reset timer", "[aggregation][timer-no-reset]")
{
    WHEN("a PTR query is injected, then another query, then timer fires once")
    {
        endpoint sender{"192.168.1.50", 5353};
        inject_query(sender, "_http._tcp.local.", dns_type::ptr, response_mode::multicast);
        inject_query(sender, "MyService._http._tcp.local.", dns_type::srv, response_mode::multicast);
        server.delay_timer().fire();

        THEN("exactly one multicast response was sent")
        {
            REQUIRE(count_multicast_responses_after(sent(), 0) == 1);
        }

        AND_THEN("no further pending timer exists")
        {
            REQUIRE_FALSE(server.delay_timer().has_pending());
        }
    }
}

SCENARIO_METHOD(live_server, "Unicast queries skip aggregation", "[aggregation][unicast-bypass]")
{
    WHEN("a QU (unicast) PTR query is injected")
    {
        endpoint sender{"10.0.0.1", 5353};
        inject_query(sender, "_http._tcp.local.", dns_type::ptr, response_mode::unicast);

        THEN("the response is sent immediately to the sender (no timer)")
        {
            REQUIRE_FALSE(sent().empty());
            REQUIRE(sent().back().dest == sender);
        }

        AND_THEN("aggregation state remains unarmed")
        {
            inject_query(sender, "_http._tcp.local.", dns_type::ptr, response_mode::multicast);
            REQUIRE(server.delay_timer().has_pending());
        }
    }
}

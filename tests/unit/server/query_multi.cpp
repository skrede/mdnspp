#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO_METHOD(live_server, "Multi-question query produces combined response", "[multi-question]")
{
    WHEN("a multi-question query with PTR and SRV is injected")
    {
        inject(endpoint{"192.168.1.50", 5353}, make_multi_question_query({
            {"_http._tcp.local.", dns_type::ptr, false},
            {"MyService._http._tcp.local.", dns_type::srv, false}
        }));

        AND_WHEN("the response timer fires")
        {
            server.delay_timer().fire();

            THEN("a combined response is sent with both PTR and SRV records")
            {
                REQUIRE_FALSE(sent().empty());
                REQUIRE(response_has<record_ptr>(last_data()));
                REQUIRE(response_has<record_srv>(last_data()));
            }
        }
    }
}

SCENARIO_METHOD(live_server, "Unmatched questions are silently skipped", "[multi-question][skip]")
{
    WHEN("a query with one matching and one non-matching question is injected")
    {
        inject(endpoint{"192.168.1.50", 5353}, make_multi_question_query({
            {"_http._tcp.local.", dns_type::ptr, false},
            {"_other._tcp.local.", dns_type::ptr, false}
        }));
        server.delay_timer().fire();

        THEN("the response contains only our PTR record, no crash")
        {
            REQUIRE_FALSE(sent().empty());
            REQUIRE(response_has<record_ptr>(last_data(), "MyService"));
            REQUIRE_FALSE(response_has<record_ptr>(last_data(), "_other"));
        }
    }
}

SCENARIO_METHOD(live_server, "All-QU queries get unicast response", "[multi-question][qu]")
{
    endpoint sender{"10.0.0.1", 5353};

    WHEN("a single-question QU query is injected")
    {
        inject(sender, make_multi_question_query({{"_http._tcp.local.", dns_type::ptr, true}}));

        THEN("the response is sent directly to the sender (unicast)")
        {
            REQUIRE_FALSE(sent().empty());
            REQUIRE(sent().back().dest == sender);
        }
    }
}

SCENARIO_METHOD(live_server, "Mixed QU queries get multicast response", "[multi-question][qu]")
{
    WHEN("a two-question query with mixed QU bits is injected")
    {
        inject(endpoint{"10.0.0.1", 5353}, make_multi_question_query({
            {"_http._tcp.local.", dns_type::ptr, true},
            {"MyService._http._tcp.local.", dns_type::srv, false}
        }));
        server.delay_timer().fire();

        THEN("the response is sent to multicast (any non-QU forces multicast)")
        {
            REQUIRE_FALSE(sent().empty());
            REQUIRE(sent().back().dest == endpoint{"224.0.0.251", 5353});
        }
    }
}

SCENARIO_METHOD(live_server, "service_server matches queries case-insensitively and answers with original case",
                "[service_server][query][case]")
{
    WHEN("an all-uppercase PTR query for the service type is injected")
    {
        inject(endpoint{"192.168.1.50", 5353},
               make_multi_question_query({{"_HTTP._TCP.LOCAL.", dns_type::ptr, false}}));
        server.delay_timer().fire();

        THEN("the server answers (RFC 6762 section 16) with case preserved on the wire")
        {
            REQUIRE_FALSE(sent().empty());
            REQUIRE(response_has<record_ptr>(last_data(), "MyService"));
        }
    }
}

SCENARIO_METHOD(live_server, "service_server answers a lowercase SRV query with the original-case owner name",
                "[service_server][query][case]")
{
    WHEN("a lowercase SRV query for the mixed-case instance name is injected")
    {
        inject(endpoint{"192.168.1.51", 5353},
               make_multi_question_query({{"myservice._http._tcp.local.", dns_type::srv, false}}));
        server.delay_timer().fire();

        THEN("the server answers with an SRV record owned by the original-case name")
        {
            REQUIRE_FALSE(sent().empty());
            REQUIRE(response_has<record_srv>(last_data(), "MyService"));
        }
    }
}

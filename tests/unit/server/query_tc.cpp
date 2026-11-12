#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO_METHOD(live_server, "TC bit on incoming query arms the tc_timer with 400-500ms window",
                "[service_server][tc][rfc6762]")
{
    WHEN("a TC query is injected from a remote sender")
    {
        inject(endpoint{"192.168.1.20", 5353}, make_tc_ptr_query("_http._tcp.local."));

        THEN("the tc_timer is armed (has_pending returns true)")
        {
            REQUIRE(server.tc_timer().has_pending());
        }

        THEN("the tc_timer duration is between 400ms and 500ms")
        {
            auto dur = server.tc_timer().last_duration();
            REQUIRE(dur >= std::chrono::milliseconds(400));
            REQUIRE(dur <= std::chrono::milliseconds(500));
        }

        THEN("the response timer is NOT armed immediately (deferred)")
        {
            REQUIRE_FALSE(server.delay_timer().has_pending());
        }
    }
}

SCENARIO_METHOD(live_server, "First TC packet from a source arms the tc_timer", "[service_server][tc][accumulation]")
{
    WHEN("a TC packet arrives from a remote sender")
    {
        inject(endpoint{"192.168.1.20", 5353}, make_tc_ptr_query("_http._tcp.local."));

        THEN("tc_timer is armed after first packet")
        {
            REQUIRE(server.tc_timer().has_pending());
        }
    }
}

SCENARIO_METHOD(live_server, "Second TC packet from same source accumulates into existing entry",
                "[service_server][tc][accumulation]")
{
    endpoint remote{"192.168.1.20", 5353};

    WHEN("two TC packets arrive from the same source")
    {
        inject(remote, make_tc_ptr_query("_http._tcp.local."));
        auto dur_after_first = server.tc_timer().last_duration();
        inject(remote, make_tc_ptr_query("_http._tcp.local."));

        THEN("tc_timer duration does not change on second packet (arm-once)")
        {
            REQUIRE(dur_after_first == server.tc_timer().last_duration());
        }

        THEN("tc_timer still has a pending handler after second packet")
        {
            REQUIRE(server.tc_timer().has_pending());
        }
    }
}

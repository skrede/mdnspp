#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstddef>
#include <algorithm>

namespace {

void fire_three_probes(server_fixture &f)
{
    f.fire();
    REQUIRE(f.sent().size() == 1);
    f.fire();
    REQUIRE(f.sent().size() == 2);
    f.fire();
    REQUIRE(f.sent().size() == 3);
}

void check_probe_sent(server_fixture &f, std::size_t index)
{
    REQUIRE(f.sent()[index].dest == mdns_group());
    REQUIRE(f.sent()[index].data.size() >= 4);
    REQUIRE(flags_of(f.sent()[index]) == 0x0000);
}

void probe_header_sections(server_fixture &f)
{
    THEN("3 probe queries were sent to 224.0.0.251:5353")
    {
        for(std::size_t i = 0; i < 3; ++i)
            check_probe_sent(f, i);
    }

    THEN("probe queries use message ID 0 (RFC 6762 section 18.1)")
    {
        for(std::size_t i = 0; i < 3; ++i)
            REQUIRE(f.header_u16(i, 0) == 0);
    }

    THEN("probe queries carry questions for the instance AND the hostname (RFC 6762 section 8.1)")
    {
        REQUIRE(f.header_u16(0, 4) == 2); // qdcount
    }

    THEN("the authority section carries the full proposed record set")
    {
        REQUIRE(f.header_u16(0, 8) == 3); // nscount: SRV, TXT, A
    }
}

}

SCENARIO("probing sends 3 probe queries to multicast", "[service_server][probing]")
{
    GIVEN("a service_server")
    {
        server_fixture f;

        WHEN("async_start is called and probing completes")
        {
            f.start();
            fire_three_probes(f);
            probe_header_sections(f);
        }
    }
}

SCENARIO("probing uses 250ms intervals", "[service_server][probing][timing]")
{
    GIVEN("a service_server")
    {
        server_fixture f;

        WHEN("async_start is called and probes are sent")
        {
            f.start();
            f.fire();

            THEN("subsequent probe timers are armed at 250ms intervals")
            {
                REQUIRE(f.server.timer().last_duration() == std::chrono::milliseconds(250));
                f.fire();
                REQUIRE(f.server.timer().last_duration() == std::chrono::milliseconds(250));
                f.fire();
                // After the third probe the same interval is the conflict window.
                REQUIRE(f.server.timer().last_duration() == std::chrono::milliseconds(250));
            }
        }
    }
}

SCENARIO("server enters live state after probe+announce sequence", "[service_server][probing][lifecycle]")
{
    GIVEN("a service_server with on_ready callback")
    {
        server_fixture f;

        WHEN("async_start is called and probe+announce completes")
        {
            f.start(record_into(f.ready));
            advance_to_live(f.server);

            THEN("on_ready fires with success")
            {
                check_succeeded(f.ready);
            }
        }
    }
}

SCENARIO("queries dropped during probing", "[service_server][probing][drop]")
{
    GIVEN("a service_server with a PTR query enqueued before start")
    {
        server_fixture f;
        endpoint sender{"192.168.1.50", 5353};
        f.server.socket().enqueue(make_ptr_query("_http._tcp.local."), sender);

        WHEN("async_start is called (query is received during probing)")
        {
            f.go_live();

            THEN("no response was sent to the querier (query was dropped during probing)")
            {
                REQUIRE_FALSE(std::ranges::any_of(f.sent(), [&](const sent_packet &p) { return p.dest == sender; }));
            }
        }
    }
}

SCENARIO("stop during probing fires on_ready with operation_canceled", "[service_server][probing][stop]")
{
    GIVEN("a service_server with on_ready and on_done callbacks")
    {
        server_fixture f;

        WHEN("async_start is called then stop() is called while probing")
        {
            f.start_recording();
            f.stop();

            THEN("on_ready fired with operation_canceled")
            {
                check_failed_with(f.ready, std::errc::operation_canceled);
            }

            AND_THEN("on_done fired with success")
            {
                check_succeeded(f.done);
            }
        }
    }
}

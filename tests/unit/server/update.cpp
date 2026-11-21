#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <utility>

namespace {

service_options announcing(uint8_t announce_count)
{
    service_options opts;
    opts.announce_count = announce_count;
    opts.respond_to_meta_queries = false;
    return opts;
}

void burst_sections(server_fixture &f)
{
    THEN("first announcement is sent immediately")
    {
        REQUIRE(f.sent().size() == 1);

        AND_WHEN("timer fires for second announcement")
        {
            f.fire();

            THEN("second announcement is sent")
            {
                REQUIRE(f.sent().size() == 2);
            }
        }
    }
}

void delayed_response_sections(server_fixture &f)
{
    THEN("the announce burst armed the response timer without touching the delay timer")
    {
        REQUIRE(f.server.timer().has_pending());       // second announcement
        REQUIRE(f.server.delay_timer().has_pending()); // delayed response intact
    }

    AND_WHEN("the delay timer fires")
    {
        auto sent_before = f.sent().size();
        f.server.delay_timer().fire();

        THEN("the delayed response still goes out")
        {
            REQUIRE(f.sent().size() == sent_before + 1);
            REQUIRE(f.sent().back().dest == mdns_group());
            REQUIRE(contains_record<record_ptr>(f.sent().back().data));
        }
    }
}

void posted_sections(server_fixture &f)
{
    THEN("a lambda was posted to the executor")
    {
        REQUIRE(f.ex.m_posted.size() == 1);

        AND_WHEN("the posted work is drained")
        {
            f.clear_sent();
            f.ex.drain_posted();

            THEN("the socket has a sent packet (first announcement of burst)")
            {
                REQUIRE_FALSE(f.sent().empty());
            }
        }
    }
}

}

SCENARIO("update_service_info sends announcement burst", "[service_server][update][burst]")
{
    GIVEN("a live service_server with announce_count=2")
    {
        server_fixture f{make_test_info(), announcing(2)};
        f.go_live();
        f.clear_sent();

        WHEN("update_service_info is called")
        {
            f.update(test_info_on_port(9090));
            burst_sections(f);
        }
    }
}

SCENARIO("update_service_info announce does not cancel a scheduled delayed response", "[service_server][update][delay]")
{
    GIVEN("a live service_server with a delayed shared-record response pending")
    {
        server_fixture f{make_test_info(), announcing(2)};
        f.go_live();
        f.clear_sent();
        // A multicast PTR query schedules a shared-record response on the dedicated delay timer (RFC 6762
        // section 6, 20-120 ms).
        f.inject(endpoint{"192.168.1.50", 5353}, make_ptr_query("_http._tcp.local."));
        REQUIRE(f.server.delay_timer().has_pending());

        WHEN("update_service_info fires an announce burst before the delay elapses")
        {
            f.update(test_info_on_port(9090));
            delayed_response_sections(f);
        }
    }
}

SCENARIO("update_service_info posts work to executor", "[service_server][update]")
{
    GIVEN("a live service_server")
    {
        server_fixture f;
        f.go_live();

        WHEN("update_service_info() is called with new service_info")
        {
            auto new_info = test_info_on_port(9090);
            new_info.txt_records = {service_txt{"version", "2.0"}};
            f.server.update_service_info(std::move(new_info));
            posted_sections(f);
        }
    }
}

SCENARIO("update_service_info sends unsolicited announcement to multicast", "[service_server][update][announcement]")
{
    GIVEN("a live service_server")
    {
        server_fixture f;
        f.go_live();

        WHEN("update_service_info() is called and posted work is drained")
        {
            f.server.update_service_info(test_info_on_port(9090));
            f.clear_sent();
            f.ex.drain_posted();

            THEN("a packet was sent to 224.0.0.251:5353")
            {
                REQUIRE_FALSE(f.sent().empty());
                REQUIRE(f.sent().back().dest == mdns_group());

                AND_THEN("the packet is non-empty DNS response data")
                {
                    REQUIRE_FALSE(f.sent().back().data.empty());
                }
            }
        }
    }
}

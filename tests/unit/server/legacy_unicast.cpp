#include "fixture.h"
#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <vector>
#include <cstdint>
#include <variant>

namespace {

endpoint legacy_sender()
{
    return endpoint{"10.0.0.1", 12345};
}

mdns_options immediate_responses()
{
    mdns_options mopts;
    mopts.response_delay_min = std::chrono::milliseconds{0};
    mopts.response_delay_max = std::chrono::milliseconds{0};
    return mopts;
}

mdns_options capped_ttl()
{
    mdns_options mopts = immediate_responses();
    mopts.legacy_unicast_ttl = std::chrono::seconds{10};
    return mopts;
}

void live_query_from(server_fixture &f, const endpoint &from)
{
    f.go_live();
    f.clear_sent();
    f.inject(from, make_ptr_query("_http._tcp.local."));
}

void check_ttls_capped(const std::vector<sent_packet> &packets)
{
    bool found_response = false;
    for(const auto &pkt : packets)
    {
        if(pkt.dest != legacy_sender())
            continue;
        found_response = true;
        for(const auto &rv : parse_response(pkt.data))
        {
            uint32_t ttl = std::visit([](const auto &r) { return r.ttl; }, rv);
            REQUIRE(ttl <= 10u);
        }
    }
    REQUIRE(found_response);
}

}

SCENARIO("Server sends unicast response to legacy unicast query (port != 5353)",
         "[service_server][legacy_unicast][rfc01]")
{
    GIVEN("a live server with default service_options (respond_to_legacy_unicast=true)")
    {
        server_fixture f;
        live_query_from(f, legacy_sender());

        WHEN("a PTR query arrives from a non-5353 port")
        {
            THEN("the response is sent directly to the legacy sender (unicast)")
            {
                REQUIRE(sent_to(f.sent(), legacy_sender()));
            }

            THEN("the response is NOT sent to the multicast group for that legacy query")
            {
                REQUIRE_FALSE(sent_to(f.sent(), mdns_group()));
            }
        }
    }
}

SCENARIO("Server respects legacy_unicast_ttl cap on legacy unicast responses",
         "[service_server][legacy_unicast][ttl]")
{
    GIVEN("a live server with legacy_unicast_ttl=10 (default)")
    {
        server_fixture f{make_test_info(), {}, capped_ttl()};
        live_query_from(f, legacy_sender());

        WHEN("the legacy unicast response is sent")
        {
            THEN("all records in the response have TTL <= 10")
            {
                check_ttls_capped(f.sent());
            }
        }
    }
}

SCENARIO("Server ignores legacy unicast when respond_to_legacy_unicast=false",
         "[service_server][legacy_unicast][disabled]")
{
    GIVEN("a live server with respond_to_legacy_unicast=false")
    {
        server_fixture f{make_test_info(), service_options{.respond_to_legacy_unicast = false}, immediate_responses()};
        live_query_from(f, legacy_sender());

        WHEN("a PTR query arrives from a non-5353 port")
        {
            THEN("no direct unicast response is sent to the legacy sender")
            {
                REQUIRE_FALSE(sent_to(f.sent(), legacy_sender()));
            }

            THEN("a multicast response timer is armed (normal multicast path)")
            {
                f.server.delay_timer().fire();
                REQUIRE(sent_to(f.sent(), mdns_group()));
            }
        }
    }
}

SCENARIO("Normal mDNS query from port 5353 uses multicast path", "[service_server][legacy_unicast][normal]")
{
    GIVEN("a live server")
    {
        server_fixture f{make_test_info(), {}, immediate_responses()};
        endpoint normal_sender{"192.168.1.50", 5353};
        live_query_from(f, normal_sender);

        WHEN("a PTR query arrives from port 5353")
        {
            THEN("no direct unicast response is sent to the sender")
            {
                REQUIRE_FALSE(sent_to(f.sent(), normal_sender));
            }
        }
    }
}

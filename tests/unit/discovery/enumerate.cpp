#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

namespace {

void enumerate_sections(discovery_fixture &f, const enumerate_outcome &types)
{
    THEN("a PTR query for _services._dns-sd._udp.local was sent")
    {
        REQUIRE_FALSE(f.sd.socket().sent_packets().empty());
        const auto &data = f.sd.socket().sent_packets()[0].data;
        REQUIRE(data.size() >= 12);
        REQUIRE(static_cast<uint8_t>(data[4]) == 0x00); // QDCOUNT
        REQUIRE(static_cast<uint8_t>(data[5]) == 0x01);
    }

    AND_THEN("the callback fires with one parsed service_type_info")
    {
        check_completed(types);
        REQUIRE(types.results.size() == 1);
        REQUIRE(types.results[0].type_name == "_http");
        REQUIRE(types.results[0].protocol == "_tcp");
        REQUIRE(types.results[0].domain == "local");
    }
}

}

SCENARIO("async_enumerate_types returns parsed service types", "[service_discovery][enumerate]")
{
    GIVEN("a service_discovery and a PTR response for the meta-query")
    {
        enumerate_outcome types;
        discovery_fixture f;
        f.enqueue(make_ptr_response("_services._dns-sd._udp.local.", "_http._tcp.local."));

        WHEN("async_enumerate_types() is called and the silence timer fires")
        {
            f.sd.async_enumerate_types(record_into(types));
            f.fire_delay();
            f.fire_silence();
            enumerate_sections(f, types);
        }
    }
}

SCENARIO("async_discover_subtype discovers subtype instances", "[service_discovery][subtype]")
{
    GIVEN("a service_discovery and a PTR response for a subtype query")
    {
        discovery_fixture f;
        f.enqueue(make_ptr_response("_printer._sub._http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("async_discover_subtype() is called and the silence timer fires")
        {
            f.sd.async_discover_subtype("_http._tcp.local.", "_printer", record_into(f.found));
            f.fire_delay();
            f.fire_silence();

            THEN("a PTR query for _printer._sub._http._tcp.local was sent")
            {
                check_sent_to_multicast(f);
            }

            AND_THEN("the callback fires with the subtype PTR record")
            {
                check_completed(f.found);
                check_single_ptr(f.found.results, "MyService");
            }
        }
    }
}

SCENARIO("discover query uses known-answer overload of build_dns_query", "[service_discovery][discover][known-answer]")
{
    GIVEN("a service_discovery instance with no enqueued responses")
    {
        discovery_fixture f;

        WHEN("async_discover() is called for the first time (m_results empty)")
        {
            f.discover();
            f.fire_delay();

            THEN("a valid DNS query packet was sent with ancount=0 (no known answers on first query)")
            {
                REQUIRE_FALSE(f.sd.socket().sent_packets().empty());
                const auto &data = f.sd.socket().sent_packets()[0].data;
                REQUIRE(data.size() >= 12);
                REQUIRE(static_cast<uint8_t>(data[6]) == 0x00); // ANCOUNT
                REQUIRE(static_cast<uint8_t>(data[7]) == 0x00);
            }
        }
    }
}

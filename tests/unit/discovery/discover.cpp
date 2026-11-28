#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

// RFC 6762 section 5.2: QM queries are delayed by 20-120 ms.
void check_first_query_pending(discovery_fixture &f)
{
    REQUIRE(f.sd.socket().sent_packets().empty());
    REQUIRE(f.sd.delay_timer().has_pending());
    REQUIRE(f.sd.delay_timer().last_duration() >= 20ms);
    REQUIRE(f.sd.delay_timer().last_duration() <= 120ms);
}

void check_query_header(const std::vector<std::byte> &data)
{
    REQUIRE(data.size() >= 12);
    REQUIRE(static_cast<uint8_t>(data[0]) == 0x00); // transaction ID
    REQUIRE(static_cast<uint8_t>(data[1]) == 0x00);
    REQUIRE(static_cast<uint8_t>(data[2]) == 0x00); // flags: standard query
    REQUIRE(static_cast<uint8_t>(data[3]) == 0x00);
    REQUIRE(static_cast<uint8_t>(data[4]) == 0x00); // QDCOUNT
    REQUIRE(static_cast<uint8_t>(data[5]) == 0x01);
    REQUIRE(static_cast<uint8_t>(data[6]) == 0x00); // ANCOUNT
    REQUIRE(static_cast<uint8_t>(data[7]) == 0x00);
}

}

SCENARIO("service_discovery constructs and discovers", "[service_discovery][create]")
{
    GIVEN("a service_discovery instance with mock_policy")
    {
        mock_executor ex;

        WHEN("constructed with 500ms silence timeout")
        {
            basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};

            THEN("it is usable (socket is empty, results empty)")
            {
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}

SCENARIO("async_discover returns PTR record from mock socket", "[service_discovery][discover]")
{
    GIVEN("a service_discovery instance and a queued PTR response")
    {
        discovery_fixture f;
        f.enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("async_discover() is called for _http._tcp.local.")
        {
            f.discover();

            THEN("results() contains one record_ptr")
            {
                check_single_ptr(f.sd.results(), "MyService");
            }
        }
    }
}

SCENARIO("async_discover fires completion callback with results", "[service_discovery][async]")
{
    GIVEN("a service_discovery instance and a queued PTR response")
    {
        discovery_fixture f;
        f.enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("async_discover() is called with a completion callback and the silence timer fires")
        {
            f.discover(record_into(f.found));
            f.fire_silence();

            THEN("the callback fires with error_code{} and the accumulated results")
            {
                check_completed(f.found);
                check_single_ptr(f.found.results, "MyService");
            }

            AND_THEN("results() accessor is still populated (completion handler received a copy)")
            {
                REQUIRE(f.sd.results().size() == 1);
            }
        }
    }
}

SCENARIO("async_discover accumulates multiple records from a single frame", "[service_discovery][discover][multi]")
{
    GIVEN("a service_discovery instance and a multi-record response enqueued")
    {
        discovery_fixture f;
        f.enqueue(make_multi_record_response());

        WHEN("async_discover() is called")
        {
            f.discover();

            THEN("results() contains both records")
            {
                REQUIRE(f.sd.results().size() >= 2);
            }
        }
    }
}

SCENARIO("async_discover sends DNS PTR query to multicast address", "[service_discovery][discover][query]")
{
    GIVEN("a service_discovery instance with no enqueued responses")
    {
        discovery_fixture f;

        WHEN("async_discover() is called for _http._tcp.local. and the section 5.2 delay elapses")
        {
            f.discover();
            check_first_query_pending(f);
            f.fire_delay();

            THEN("a DNS query was sent to 224.0.0.251:5353")
            {
                check_sent_to_multicast(f);
            }

            AND_THEN("the query packet has correct DNS header (id=0, flags=0, qdcount=1)")
            {
                check_query_header(f.sd.socket().sent_packets()[0].data);
            }
        }
    }
}

SCENARIO("async_discover ignores answer records carried in query packets", "[service_discovery][qr-flag]")
{
    GIVEN("a service_discovery and a QUERY packet (QR=0) carrying a PTR known answer")
    {
        auto pkt = make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local.");
        pkt[2] = std::byte{0x00};
        pkt[3] = std::byte{0x00};

        discovery_fixture f;
        f.enqueue(pkt);

        WHEN("async_discover() is called for the matching type")
        {
            f.discover();

            THEN("results() stays empty -- query packets are not answers")
            {
                REQUIRE(f.sd.results().empty());
            }
        }
    }
}

SCENARIO("async_discover skips malformed records and returns valid ones", "[service_discovery][discover][malformed]")
{
    GIVEN("a DNS frame with a valid PTR and a truncated A record")
    {
        discovery_fixture f;
        f.enqueue(make_malformed_a_response());

        WHEN("async_discover() is called")
        {
            f.discover();

            THEN("results() contains only the valid PTR record")
            {
                check_single_ptr(f.sd.results(), "Good");
            }
        }
    }
}

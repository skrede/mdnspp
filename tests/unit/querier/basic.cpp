#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <cstdint>

namespace {

void check_query_header(const std::vector<std::byte> &data)
{
    REQUIRE(data.size() >= 12);
    // Transaction ID: 0x0000
    REQUIRE(static_cast<uint8_t>(data[0]) == 0x00);
    REQUIRE(static_cast<uint8_t>(data[1]) == 0x00);
    // Flags: 0x0000 (standard query)
    REQUIRE(static_cast<uint8_t>(data[2]) == 0x00);
    REQUIRE(static_cast<uint8_t>(data[3]) == 0x00);
    // QDCOUNT: 1
    REQUIRE(static_cast<uint8_t>(data[4]) == 0x00);
    REQUIRE(static_cast<uint8_t>(data[5]) == 0x01);
    // ANCOUNT: 0
    REQUIRE(static_cast<uint8_t>(data[6]) == 0x00);
    REQUIRE(static_cast<uint8_t>(data[7]) == 0x00);
}

void sent_query_sections(querier_fixture &f)
{
    THEN("a DNS query was sent to 224.0.0.251:5353")
    {
        REQUIRE_FALSE(f.q.socket().sent_packets().empty());
        const auto &sent = f.q.socket().sent_packets()[0];
        REQUIRE(sent.dest == endpoint{"224.0.0.251", 5353});
    }

    AND_THEN("the query packet has correct DNS header (id=0, flags=0, qdcount=1)")
    {
        check_query_header(f.q.socket().sent_packets()[0].data);
    }

    AND_THEN("the query packet contains qtype=1 (A) in the question section")
    {
        const auto &data = f.q.socket().sent_packets()[0].data;
        // 12-byte header + 14-byte name (\x06myhost\x05local\x00) puts QTYPE at offset 26.
        REQUIRE(data.size() >= 28);
        std::size_t qtype_offset = data.size() - 4; // qtype(2) + qclass(2)
        REQUIRE(static_cast<uint8_t>(data[qtype_offset]) == 0x00);
        REQUIRE(static_cast<uint8_t>(data[qtype_offset + 1]) == 0x01); // A = 1
    }
}

}

SCENARIO("async_query returns A record from mock socket", "[querier][query][A]")
{
    GIVEN("a querier instance and an A response for myhost.local. enqueued")
    {
        querier_fixture f;
        f.enqueue(make_a_response("myhost.local.", 192, 168, 1, 1));

        WHEN("async_query() is called for myhost.local. with qtype=1 (A)")
        {
            f.query();

            THEN("results() contains one record_a")
            {
                check_single_a(f.q.results(), "192.168.1.1");
            }
        }
    }
}

SCENARIO("async_query fires completion callback with results", "[querier][async]")
{
    GIVEN("a querier instance and an A response for myhost.local. enqueued")
    {
        querier_fixture f;
        f.enqueue(make_a_response("myhost.local.", 10, 0, 0, 1));

        WHEN("async_query() is called with a completion callback and the silence timer fires")
        {
            f.query(record_into(f.done));
            f.fire_silence();

            THEN("the callback fires with error_code{} and the accumulated results")
            {
                REQUIRE(f.done.fired);
                REQUIRE_FALSE(f.done.ec);
                check_single_a(f.done.results, "10.0.0.1");
            }

            AND_THEN("results() accessor is still populated (completion handler received a copy)")
            {
                REQUIRE(f.q.results().size() == 1);
            }
        }
    }
}

SCENARIO("async_query sends correct DNS query packet", "[querier][query][packet]")
{
    GIVEN("a querier instance with no enqueued responses")
    {
        querier_fixture f;

        WHEN("async_query() is called for myhost.local. with qtype=1 (A)")
        {
            f.query();
            f.fire_delay();
            sent_query_sections(f);
        }
    }
}

SCENARIO("async_query accumulates multiple records from a single frame", "[querier][query][multi]")
{
    GIVEN("a querier instance and a multi-record response enqueued")
    {
        querier_fixture f;
        f.enqueue(make_multi_record_response());

        WHEN("async_query() is called")
        {
            f.query();

            THEN("results() contains all records from the frame")
            {
                REQUIRE(f.q.results().size() >= 2);
            }
        }
    }
}

SCENARIO("async_query skips malformed records and returns valid ones", "[querier][query][malformed]")
{
    GIVEN("a DNS frame with a valid A record and an invalid A record (wrong rdlength)")
    {
        querier_fixture f;
        f.enqueue(make_malformed_a_response());

        WHEN("async_query() is called")
        {
            f.query(ignore_completion(), "good.local.");

            THEN("results() contains only the valid A record")
            {
                check_single_a(f.q.results(), "1.2.3.4");
            }
        }
    }
}

SCENARIO("querier ignores answer records carried in query packets", "[querier][qr-flag]")
{
    GIVEN("a querier and a QUERY packet (QR=0) carrying a known-answer A record")
    {
        auto pkt = make_a_response("myhost.local.", 192, 168, 1, 1);
        pkt[2] = std::byte{0x00};
        pkt[3] = std::byte{0x00};
        querier_fixture f;
        f.enqueue(pkt);

        WHEN("async_query() is called for the matching name")
        {
            f.query();

            THEN("results() stays empty -- query packets are not answers")
            {
                REQUIRE(f.q.results().empty());
            }
        }
    }
}

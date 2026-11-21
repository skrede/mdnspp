#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

namespace {

void start_pending_query(querier_fixture &f)
{
    f.query();
    REQUIRE(f.q.socket().sent_packets().empty());
    REQUIRE(f.q.delay_timer().has_pending());
}

void pending_delay_sections(querier_fixture &f)
{
    THEN("no query packet is sent immediately")
    {
        REQUIRE(f.q.socket().sent_packets().empty());
    }

    THEN("the delay timer has a pending handler")
    {
        REQUIRE(f.q.delay_timer().has_pending());
    }

    THEN("the delay timer duration is between 20ms and 120ms")
    {
        auto d = f.q.delay_timer().last_duration();
        REQUIRE(d >= 20ms);
        REQUIRE(d <= 120ms);
    }
}

}

SCENARIO("QM query delays send by 20-120ms", "[querier][delay]")
{
    GIVEN("a querier instance with no enqueued responses")
    {
        querier_fixture f;

        WHEN("async_query is called with multicast mode (default)")
        {
            f.query();
            pending_delay_sections(f);

            AND_WHEN("the delay timer fires")
            {
                f.fire_delay();

                THEN("the query packet is now sent")
                {
                    REQUIRE_FALSE(f.q.socket().sent_packets().empty());
                }
            }
        }
    }
}

SCENARIO("QU query sends immediately without delay", "[querier][delay]")
{
    GIVEN("a querier instance with no enqueued responses")
    {
        querier_fixture f;

        WHEN("async_query is called with unicast mode")
        {
            f.query(ignore_completion(), "myhost.local.", response_mode::unicast);

            THEN("the query packet is sent immediately")
            {
                REQUIRE_FALSE(f.q.socket().sent_packets().empty());
            }

            THEN("the delay timer has no pending handler")
            {
                REQUIRE_FALSE(f.q.delay_timer().has_pending());
            }
        }
    }
}

SCENARIO("duplicate QM question suppresses pending query", "[querier][suppression]")
{
    GIVEN("a querier with a pending QM query")
    {
        querier_fixture f;
        start_pending_query(f);

        WHEN("a matching QM query packet is injected during the delay window")
        {
            f.inject(make_dns_query_packet("myhost.local.", 1, false));

            AND_WHEN("the delay timer fires")
            {
                f.fire_delay();

                THEN("no query packet was sent by the querier (suppressed)")
                {
                    REQUIRE(f.q.socket().sent_packets().empty());
                }
            }
        }
    }
}

SCENARIO("duplicate question carrying known answers does NOT suppress", "[querier][suppression][7.3]")
{
    GIVEN("a querier with a pending QM query")
    {
        querier_fixture f;
        start_pending_query(f);

        WHEN("a matching QM query with a non-empty known-answer section is injected")
        {
            // RFC 6762 section 7.3: suppression is permitted only when the observed known-answer section holds nothing
            // we do not also hold; we hold no answers, so a KA-bearing query must not suppress ours.
            f.inject(make_known_answer_query("myhost.local."));

            AND_WHEN("the delay timer fires")
            {
                f.fire_delay();

                THEN("the query packet WAS sent (KA-bearing query does not suppress)")
                {
                    REQUIRE_FALSE(f.q.socket().sent_packets().empty());
                }
            }
        }
    }
}

SCENARIO("QU duplicate does NOT suppress pending QM query", "[querier][suppression]")
{
    GIVEN("a querier with a pending QM query")
    {
        querier_fixture f;
        start_pending_query(f);

        WHEN("a matching QU query packet is injected during the delay window")
        {
            f.inject(make_dns_query_packet("myhost.local.", 1, true));

            AND_WHEN("the delay timer fires")
            {
                f.fire_delay();

                THEN("the query packet WAS sent (QU does not suppress)")
                {
                    REQUIRE_FALSE(f.q.socket().sent_packets().empty());
                }
            }
        }
    }
}

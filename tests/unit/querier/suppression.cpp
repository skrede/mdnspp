#include "helpers.h"

SCENARIO("QM query delays send by 20-120ms", "[querier][delay]")
{
    GIVEN("a querier instance with no enqueued responses")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

        WHEN("async_query is called with multicast mode (default)")
        {
            q.async_query("myhost.local.", dns_type::a,
                          [](std::error_code, std::vector<mdns_record_variant>)
                          {
                          });

            THEN("no query packet is sent immediately")
            {
                REQUIRE(q.socket().sent_packets().empty());
            }

            THEN("the delay timer has a pending handler")
            {
                REQUIRE(q.delay_timer().has_pending());
            }

            THEN("the delay timer duration is between 20ms and 120ms")
            {
                auto d = q.delay_timer().last_duration();
                REQUIRE(d >= 20ms);
                REQUIRE(d <= 120ms);
            }

            AND_WHEN("the delay timer fires")
            {
                q.delay_timer().fire();

                THEN("the query packet is now sent")
                {
                    REQUIRE_FALSE(q.socket().sent_packets().empty());
                }
            }
        }
    }
}

SCENARIO("QU query sends immediately without delay", "[querier][delay]")
{
    GIVEN("a querier instance with no enqueued responses")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

        WHEN("async_query is called with unicast mode")
        {
            q.async_query("myhost.local.", dns_type::a,
                          [](std::error_code, std::vector<mdns_record_variant>)
                          {
                          },
                          response_mode::unicast);

            THEN("the query packet is sent immediately")
            {
                REQUIRE_FALSE(q.socket().sent_packets().empty());
            }

            THEN("the delay timer has no pending handler")
            {
                REQUIRE_FALSE(q.delay_timer().has_pending());
            }
        }
    }
}

SCENARIO("duplicate QM question suppresses pending query", "[querier][suppression]")
{
    GIVEN("a querier with a pending QM query")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

        q.async_query("myhost.local.", dns_type::a,
                      [](std::error_code, std::vector<mdns_record_variant>)
                      {
                      });

        // Verify query is not yet sent (delayed)
        REQUIRE(q.socket().sent_packets().empty());
        REQUIRE(q.delay_timer().has_pending());

        WHEN("a matching QM query packet is injected during the delay window")
        {
            auto dup_query = make_dns_query_packet("myhost.local.", 1, false); // QM (not QU)
            q.socket().inject_receive(endpoint{}, dup_query);

            AND_WHEN("the delay timer fires")
            {
                q.delay_timer().fire();

                THEN("no query packet was sent by the querier (suppressed)")
                {
                    REQUIRE(q.socket().sent_packets().empty());
                }
            }
        }
    }
}

SCENARIO("duplicate question carrying known answers does NOT suppress", "[querier][suppression][7.3]")
{
    GIVEN("a querier with a pending QM query")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

        q.async_query("myhost.local.", dns_type::a,
                      [](std::error_code, std::vector<mdns_record_variant>)
                      {
                      });

        REQUIRE(q.socket().sent_packets().empty());
        REQUIRE(q.delay_timer().has_pending());

        WHEN("a matching QM query with a non-empty known-answer section is injected")
        {
            // RFC 6762 section 7.3: suppression is permitted only when the
            // observed known-answer section contains nothing we do not also
            // hold. We hold no answers, so a KA-bearing query must not
            // suppress ours.
            auto dup_query = make_dns_query_packet("myhost.local.", 1, false);
            auto ka = make_a_response("myhost.local.", 192, 168, 1, 1);

            // Splice the response's answer record into the query packet and
            // bump ancount to 1 (the answer RR starts after the 12-byte header).
            dup_query.insert(dup_query.end(), ka.begin() + 12, ka.end());
            dup_query[7] = static_cast<std::byte>(0x01);

            q.socket().inject_receive(endpoint{}, dup_query);

            AND_WHEN("the delay timer fires")
            {
                q.delay_timer().fire();

                THEN("the query packet WAS sent (KA-bearing query does not suppress)")
                {
                    REQUIRE_FALSE(q.socket().sent_packets().empty());
                }
            }
        }
    }
}

SCENARIO("QU duplicate does NOT suppress pending QM query", "[querier][suppression]")
{
    GIVEN("a querier with a pending QM query")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

        q.async_query("myhost.local.", dns_type::a,
                      [](std::error_code, std::vector<mdns_record_variant>)
                      {
                      });

        REQUIRE(q.socket().sent_packets().empty());
        REQUIRE(q.delay_timer().has_pending());

        WHEN("a matching QU query packet is injected during the delay window")
        {
            auto qu_query = make_dns_query_packet("myhost.local.", 1, true); // QU bit set
            q.socket().inject_receive(endpoint{}, qu_query);

            AND_WHEN("the delay timer fires")
            {
                q.delay_timer().fire();

                THEN("the query packet WAS sent (QU does not suppress)")
                {
                    REQUIRE_FALSE(q.socket().sent_packets().empty());
                }
            }
        }
    }
}

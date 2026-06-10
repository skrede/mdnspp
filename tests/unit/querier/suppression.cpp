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

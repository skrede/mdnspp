#include "helpers.h"

SCENARIO("querier constructs and is usable", "[querier][create]")
{
    GIVEN("a querier instance with mock_policy")
    {
        mock_executor ex;

        WHEN("constructed with 500ms silence timeout")
        {
            basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

            THEN("it is usable (socket is empty, results empty)")
            {
                REQUIRE(q.socket().queue_empty());
                REQUIRE(q.results().empty());
            }
        }
    }
}

SCENARIO("async_query returns A record from mock socket", "[querier][query][A]")
{
    GIVEN("a querier instance and an A response for myhost.local. enqueued")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};
        q.socket().enqueue(make_a_response("myhost.local.", 192, 168, 1, 1));

        WHEN("async_query() is called for myhost.local. with qtype=1 (A)")
        {
            q.async_query("myhost.local.", dns_type::a,
                          [](std::error_code, std::vector<mdns_record_variant>)
                          {
                          });

            THEN("results() contains one record_a")
            {
                REQUIRE(q.results().size() == 1);
                REQUIRE(std::holds_alternative<record_a>(q.results()[0]));

                const auto &a = std::get<record_a>(q.results()[0]);
                REQUIRE(a.address_string == "192.168.1.1");
            }
        }
    }
}

SCENARIO("async_query fires completion callback with results", "[querier][async]")
{
    GIVEN("a querier instance and an A response for myhost.local. enqueued")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};
        q.socket().enqueue(make_a_response("myhost.local.", 10, 0, 0, 1));

        WHEN("async_query() is called with a completion callback and the silence timer fires")
        {
            std::error_code received_ec;
            std::vector<mdns_record_variant> received_results;
            bool callback_fired = false;

            q.async_query("myhost.local.", dns_type::a,
                          [&](std::error_code ec, std::vector<mdns_record_variant> results)
                          {
                              callback_fired = true;
                              received_ec = ec;
                              received_results = std::move(results);
                          });

            // mock_socket drains the queue synchronously during async_query(),
            // but the silence timer must be fired manually to trigger the completion callback.
            q.timer().fire();

            THEN("the callback fires with error_code{} and the accumulated results")
            {
                REQUIRE(callback_fired);
                REQUIRE_FALSE(received_ec);
                REQUIRE(received_results.size() == 1);
                REQUIRE(std::holds_alternative<record_a>(received_results[0]));
                const auto &a = std::get<record_a>(received_results[0]);
                REQUIRE(a.address_string == "10.0.0.1");
            }

            AND_THEN("results() accessor is still populated (completion handler received a copy)")
            {
                REQUIRE(q.results().size() == 1);
            }
        }
    }
}

SCENARIO("async_query sends correct DNS query packet", "[querier][query][packet]")
{
    GIVEN("a querier instance with no enqueued responses")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

        WHEN("async_query() is called for myhost.local. with qtype=1 (A)")
        {
            q.async_query("myhost.local.", dns_type::a,
                          [](std::error_code, std::vector<mdns_record_variant>)
                          {
                          });

            // QM query is delayed — fire the delay timer to send
            q.delay_timer().fire();

            THEN("a DNS query was sent to 224.0.0.251:5353")
            {
                REQUIRE_FALSE(q.socket().sent_packets().empty());
                const auto &sent = q.socket().sent_packets()[0];
                REQUIRE(sent.dest == endpoint{"224.0.0.251", 5353});
            }

            AND_THEN("the query packet has correct DNS header (id=0, flags=0, qdcount=1)")
            {
                const auto &data = q.socket().sent_packets()[0].data;
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

            AND_THEN("the query packet contains qtype=1 (A) in the question section")
            {
                const auto &data = q.socket().sent_packets()[0].data;
                // Header is 12 bytes, followed by encoded name for "myhost.local."
                // Name: \x06myhost\x05local\x00 = 1+6+1+5+1 = 14 bytes
                // QTYPE starts at offset 12 + 14 = 26
                REQUIRE(data.size() >= 28);
                size_t qtype_offset = data.size() - 4; // qtype(2) + qclass(2)
                REQUIRE(static_cast<uint8_t>(data[qtype_offset]) == 0x00);
                REQUIRE(static_cast<uint8_t>(data[qtype_offset + 1]) == 0x01); // A = 1
            }
        }
    }
}

SCENARIO("async_query accumulates multiple records from a single frame", "[querier][query][multi]")
{
    GIVEN("a querier instance and a multi-record response enqueued")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};
        q.socket().enqueue(make_multi_record_response());

        WHEN("async_query() is called")
        {
            q.async_query("myhost.local.", dns_type::a,
                          [](std::error_code, std::vector<mdns_record_variant>)
                          {
                          });

            THEN("results() contains all records from the frame")
            {
                REQUIRE(q.results().size() >= 2);
            }
        }
    }
}

SCENARIO("async_query skips malformed records and returns valid ones", "[querier][query][malformed]")
{
    GIVEN("a DNS frame with a valid A record and an invalid A record (wrong rdlength)")
    {
        // Build a packet manually: 2 answer RRs
        // First: valid A record
        // Second: A record with rdlength=5 (invalid — parse::a checks rdlength==4)
        std::vector<std::byte> pkt;
        push_u16_be(pkt, 0x0000); // id
        push_u16_be(pkt, 0x8400); // flags (response)
        push_u16_be(pkt, 0x0000); // qdcount
        push_u16_be(pkt, 0x0002); // ancount = 2
        push_u16_be(pkt, 0x0000); // nscount
        push_u16_be(pkt, 0x0000); // arcount

        // RR 1: valid A record for "good.local." -> 1.2.3.4
        auto good_enc = encode_name("good.local.");
        pkt.insert(pkt.end(), good_enc.begin(), good_enc.end());
        push_u16_be(pkt, 1);      // type A
        push_u16_be(pkt, 0x0001); // class IN
        push_u32_be(pkt, 120);    // ttl
        push_u16_be(pkt, 4);      // rdlength = 4 (valid)
        pkt.push_back(static_cast<std::byte>(1));
        pkt.push_back(static_cast<std::byte>(2));
        pkt.push_back(static_cast<std::byte>(3));
        pkt.push_back(static_cast<std::byte>(4));

        // RR 2: A record with rdlength=5 (invalid — parse::a checks rdlength==4)
        auto bad_enc = encode_name("bad.local.");
        pkt.insert(pkt.end(), bad_enc.begin(), bad_enc.end());
        push_u16_be(pkt, 1); // type A
        push_u16_be(pkt, 0x0001);
        push_u32_be(pkt, 120);
        push_u16_be(pkt, 5); // rdlength=5 (invalid for type A)
        pkt.push_back(static_cast<std::byte>(5));
        pkt.push_back(static_cast<std::byte>(6));
        pkt.push_back(static_cast<std::byte>(7));
        pkt.push_back(static_cast<std::byte>(8));
        pkt.push_back(static_cast<std::byte>(0)); // 5th byte

        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};
        q.socket().enqueue(pkt);

        WHEN("async_query() is called")
        {
            q.async_query("good.local.", dns_type::a,
                          [](std::error_code, std::vector<mdns_record_variant>)
                          {
                          });

            THEN("results() contains only the valid A record")
            {
                REQUIRE(q.results().size() == 1);
                REQUIRE(std::holds_alternative<record_a>(q.results()[0]));
                const auto &a = std::get<record_a>(q.results()[0]);
                REQUIRE(a.address_string == "1.2.3.4");
            }
        }
    }
}

SCENARIO("querier non-throwing constructor sets ec on success", "[querier][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_querier<mock_policy> is constructed with the ec overload")
        {
            basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}, {}, {}, ec};

            THEN("ec is clear and the querier is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(q.socket().queue_empty());
                REQUIRE(q.results().empty());
            }
        }
    }
}

SCENARIO("querier is move-constructible before async_query", "[querier][move]")
{
    GIVEN("a querier constructed but not started")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

        WHEN("move-constructed into a new querier")
        {
            basic_querier<mock_policy> moved{std::move(q)};

            THEN("the moved-to querier is usable")
            {
                REQUIRE(moved.socket().queue_empty());
                REQUIRE(moved.results().empty());
            }
        }
    }
}

SCENARIO("querier stop without starting does not crash", "[querier][stop][no-start]")
{
    GIVEN("a querier constructed but never started")
    {
        mock_executor ex;
        basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}};

        WHEN("stop() is called")
        {
            THEN("no crash or handler fire occurs")
            {
                REQUIRE_NOTHROW(q.stop());
            }
        }
    }
}

SCENARIO("basic_querier with socket_options", "[querier][socket_options]")
{
    GIVEN("a socket_options with multicast_ttl = 100")
    {
        mock_executor ex;
        socket_options opts{.multicast_ttl = uint8_t{100}};

        WHEN("basic_querier<mock_policy> is constructed with socket_options")
        {
            basic_querier<mock_policy> q{ex, query_options{.silence_timeout = 500ms}, opts};

            THEN("the socket stores the options with ttl = 100")
            {
                REQUIRE(q.socket().options().multicast_ttl == 100);
                REQUIRE(q.socket().queue_empty());
                REQUIRE(q.results().empty());
            }
        }
    }
}

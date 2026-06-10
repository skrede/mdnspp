#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

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
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};
        sd.socket().enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("async_discover() is called for _http._tcp.local.")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, std::vector<mdns_record_variant>)
                              {
                              });

            THEN("results() contains one record_ptr")
            {
                REQUIRE(sd.results().size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(sd.results()[0]));

                const auto &ptr = std::get<record_ptr>(sd.results()[0]);
                REQUIRE(ptr.ptr_name.find("myservice") != dns_name::npos);
            }
        }
    }
}

SCENARIO("async_discover fires completion callback with results", "[service_discovery][async]")
{
    GIVEN("a service_discovery instance and a queued PTR response")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};
        sd.socket().enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("async_discover() is called with a completion callback and the silence timer fires")
        {
            std::error_code received_ec;
            std::vector<mdns_record_variant> received_results;
            bool callback_fired = false;

            sd.async_discover("_http._tcp.local.",
                              [&](std::error_code ec, std::vector<mdns_record_variant> results)
                              {
                                  callback_fired = true;
                                  received_ec = ec;
                                  received_results = std::move(results);
                              });

            // mock_socket drains the queue synchronously during async_discover(),
            // but the silence timer must be fired manually to trigger the completion callback.
            sd.timer().fire();

            THEN("the callback fires with error_code{} and the accumulated results")
            {
                REQUIRE(callback_fired);
                REQUIRE_FALSE(received_ec);
                REQUIRE(received_results.size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(received_results[0]));
                const auto &ptr = std::get<record_ptr>(received_results[0]);
                REQUIRE(ptr.ptr_name.find("myservice") != dns_name::npos);
            }

            AND_THEN("results() accessor is still populated (completion handler received a copy)")
            {
                REQUIRE(sd.results().size() == 1);
            }
        }
    }
}

SCENARIO("async_discover accumulates multiple records from a single frame", "[service_discovery][discover][multi]")
{
    GIVEN("a service_discovery instance and a multi-record response enqueued")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};
        sd.socket().enqueue(make_multi_record_response());

        WHEN("async_discover() is called")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, std::vector<mdns_record_variant>)
                              {
                              });

            THEN("results() contains both records")
            {
                REQUIRE(sd.results().size() >= 2);
            }
        }
    }
}

SCENARIO("async_discover sends DNS PTR query to multicast address", "[service_discovery][discover][query]")
{
    GIVEN("a service_discovery instance with no enqueued responses")
    {
        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};

        WHEN("async_discover() is called for _http._tcp.local.")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, std::vector<mdns_record_variant>)
                              {
                              });

            THEN("a DNS query was sent to 224.0.0.251:5353")
            {
                REQUIRE_FALSE(sd.socket().sent_packets().empty());
                const auto &sent = sd.socket().sent_packets()[0];
                REQUIRE(sent.dest == endpoint{"224.0.0.251", 5353});
            }

            AND_THEN("the query packet has correct DNS header (id=0, flags=0, qdcount=1)")
            {
                const auto &data = sd.socket().sent_packets()[0].data;
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
        }
    }
}

SCENARIO("async_discover skips malformed records and returns valid ones", "[service_discovery][discover][malformed]")
{
    GIVEN("a DNS frame with a valid PTR and a truncated A record")
    {
        // Build a packet manually: 2 answer RRs
        // First: valid PTR
        // Second: A record with rdlength=5 (invalid — parse::a checks length==4)
        std::vector<std::byte> pkt;
        push_u16_be(pkt, 0x0000); // id
        push_u16_be(pkt, 0x8400); // flags (response)
        push_u16_be(pkt, 0x0000); // qdcount
        push_u16_be(pkt, 0x0002); // ancount = 2
        push_u16_be(pkt, 0x0000); // nscount
        push_u16_be(pkt, 0x0000); // arcount

        // RR 1: valid PTR record
        auto owner_enc = encode_name("_http._tcp.local.");
        auto target_enc = encode_name("Good._http._tcp.local.");
        pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
        push_u16_be(pkt, 12);
        push_u16_be(pkt, 0x0001);
        push_u32_be(pkt, 4500);
        push_u16_be(pkt, static_cast<uint16_t>(target_enc.size()));
        pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

        // RR 2: A record with rdlength=5 (invalid for type A)
        auto host_enc = encode_name("bad.local.");
        pkt.insert(pkt.end(), host_enc.begin(), host_enc.end());
        push_u16_be(pkt, 1); // type A
        push_u16_be(pkt, 0x0001);
        push_u32_be(pkt, 120);
        push_u16_be(pkt, 5); // rdlength=5 (invalid for type A — parse::a checks length==4)
        pkt.push_back(static_cast<std::byte>(192));
        pkt.push_back(static_cast<std::byte>(168));
        pkt.push_back(static_cast<std::byte>(0));
        pkt.push_back(static_cast<std::byte>(1));
        pkt.push_back(static_cast<std::byte>(0)); // 5th byte — makes rdlength consistent

        mock_executor ex;
        basic_service_discovery<mock_policy> sd{ex, query_options{.silence_timeout = 500ms}};
        sd.socket().enqueue(pkt);

        WHEN("async_discover() is called")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, std::vector<mdns_record_variant>)
                              {
                              });

            THEN("results() contains only the valid PTR record")
            {
                REQUIRE(sd.results().size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(sd.results()[0]));
                const auto &ptr = std::get<record_ptr>(sd.results()[0]);
                REQUIRE(ptr.ptr_name.find("good") != dns_name::npos);
            }
        }
    }
}

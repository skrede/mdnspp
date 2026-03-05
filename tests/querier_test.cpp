// tests/querier_test.cpp
// querier<MockPolicy> unit tests — Phase 7, Plan 07-03
// Tests the full async_query() flow via MockPolicy.

#include "mdnspp/querier.h"
#include "mdnspp/testing/mock_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <span>
#include <chrono>
#include <string>
#include <array>

using namespace mdnspp;
using namespace mdnspp::testing;
using namespace std::chrono_literals;
using mdnspp::dns_type;

// ---------------------------------------------------------------------------
// Byte-building helpers
// ---------------------------------------------------------------------------

static std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
{
    std::vector<std::byte> v;
    v.reserve(vals.size());
    for (auto b : vals)
        v.push_back(static_cast<std::byte>(b));
    return v;
}

static void push_u16_be(std::vector<std::byte> &buf, uint16_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v >> 8)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

static void push_u32_be(std::vector<std::byte> &buf, uint32_t v)
{
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 24) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 16) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >>  8) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>( v        & 0xFF)));
}

// Encode a DNS name to wire label format (no compression).
static std::vector<std::byte> encode_name(std::string_view name)
{
    std::vector<std::byte> result;
    if (!name.empty() && name.back() == '.')
        name.remove_suffix(1);

    size_t pos = 0;
    while (pos < name.size())
    {
        size_t dot = name.find('.', pos);
        if (dot == std::string_view::npos)
            dot = name.size();
        size_t len = dot - pos;
        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(len)));
        for (size_t i = pos; i < dot; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(name[i])));
        pos = (dot < name.size()) ? dot + 1 : name.size();
    }
    result.push_back(static_cast<std::byte>(0x00)); // root label
    return result;
}

// Builds a mDNS response with one A record (type=1).
static std::vector<std::byte> make_a_response(std::string_view name,
                                               uint8_t a, uint8_t b,
                                               uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags (response|authoritative)
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0001); // ancount = 1
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    auto owner_enc = encode_name(name);
    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 1);      // type A
    push_u16_be(pkt, 0x0001); // class IN
    push_u32_be(pkt, 120);    // ttl
    push_u16_be(pkt, 4);      // rdlength = 4
    pkt.push_back(static_cast<std::byte>(a));
    pkt.push_back(static_cast<std::byte>(b));
    pkt.push_back(static_cast<std::byte>(c));
    pkt.push_back(static_cast<std::byte>(d));

    return pkt;
}

// Builds a mDNS response with one SRV record (type=33).
static std::vector<std::byte> make_srv_response(std::string_view name,
                                                 std::string_view target,
                                                 uint16_t port)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0001); // ancount = 1
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    auto owner_enc  = encode_name(name);
    auto target_enc = encode_name(target);

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 33);     // type SRV
    push_u16_be(pkt, 0x0001); // class IN
    push_u32_be(pkt, 4500);   // ttl

    // SRV rdata: priority(2) + weight(2) + port(2) + target name
    uint16_t rdlength = static_cast<uint16_t>(6 + target_enc.size());
    push_u16_be(pkt, rdlength);
    push_u16_be(pkt, 0);      // priority
    push_u16_be(pkt, 0);      // weight
    push_u16_be(pkt, port);   // port
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    return pkt;
}

// Builds a mDNS response with one AAAA record (type=28).
static std::vector<std::byte> make_aaaa_response(std::string_view name,
                                                   std::array<uint8_t, 16> addr)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0001); // ancount = 1
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    auto owner_enc = encode_name(name);
    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 28);     // type AAAA
    push_u16_be(pkt, 0x0001); // class IN
    push_u32_be(pkt, 120);    // ttl
    push_u16_be(pkt, 16);     // rdlength = 16

    for (uint8_t b : addr)
        pkt.push_back(static_cast<std::byte>(b));

    return pkt;
}

// Builds a mDNS response with two RRs: an A and a SRV record.
static std::vector<std::byte> make_multi_record_response()
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0002); // ancount = 2
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    // First RR: A record for "myhost.local." -> 192.168.1.1
    auto a_enc = encode_name("myhost.local.");
    pkt.insert(pkt.end(), a_enc.begin(), a_enc.end());
    push_u16_be(pkt, 1);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 4);
    pkt.push_back(static_cast<std::byte>(192));
    pkt.push_back(static_cast<std::byte>(168));
    pkt.push_back(static_cast<std::byte>(1));
    pkt.push_back(static_cast<std::byte>(1));

    // Second RR: SRV record for "myservice._tcp.local." port 8080
    auto srv_name_enc   = encode_name("myservice._tcp.local.");
    auto srv_target_enc = encode_name("myhost.local.");
    pkt.insert(pkt.end(), srv_name_enc.begin(), srv_name_enc.end());
    push_u16_be(pkt, 33);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);
    push_u16_be(pkt, static_cast<uint16_t>(6 + srv_target_enc.size()));
    push_u16_be(pkt, 0);   // priority
    push_u16_be(pkt, 0);   // weight
    push_u16_be(pkt, 8080); // port
    pkt.insert(pkt.end(), srv_target_enc.begin(), srv_target_enc.end());

    return pkt;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

SCENARIO("querier constructs and is usable", "[querier][create]")
{
    GIVEN("a querier instance with MockPolicy")
    {
        mock_executor ex;

        WHEN("constructed with 500ms silence timeout")
        {
            querier<MockPolicy> q{ex, 500ms};

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
        querier<MockPolicy> q{ex, 500ms};
        q.socket().enqueue(make_a_response("myhost.local.", 192, 168, 1, 1));

        WHEN("async_query() is called for myhost.local. with qtype=1 (A)")
        {
            q.async_query("myhost.local.", dns_type::a,
                [](std::error_code, std::vector<mdns_record_variant>) {});

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
        querier<MockPolicy> q{ex, 500ms};
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

            // MockSocket drains the queue synchronously during async_query(),
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
        querier<MockPolicy> q{ex, 500ms};

        WHEN("async_query() is called for myhost.local. with qtype=1 (A)")
        {
            q.async_query("myhost.local.", dns_type::a,
                [](std::error_code, std::vector<mdns_record_variant>) {});

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
                REQUIRE(static_cast<uint8_t>(data[qtype_offset])     == 0x00);
                REQUIRE(static_cast<uint8_t>(data[qtype_offset + 1]) == 0x01); // A = 1
            }
        }
    }
}

SCENARIO("async_query accumulates multiple records from a single frame",
         "[querier][query][multi]")
{
    GIVEN("a querier instance and a multi-record response enqueued")
    {
        mock_executor ex;
        querier<MockPolicy> q{ex, 500ms};
        q.socket().enqueue(make_multi_record_response());

        WHEN("async_query() is called")
        {
            q.async_query("myhost.local.", dns_type::a,
                [](std::error_code, std::vector<mdns_record_variant>) {});

            THEN("results() contains all records from the frame")
            {
                REQUIRE(q.results().size() >= 2);
            }
        }
    }
}

SCENARIO("async_query skips malformed records and returns valid ones",
         "[querier][query][malformed]")
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
        push_u16_be(pkt, 1);      // type A
        push_u16_be(pkt, 0x0001);
        push_u32_be(pkt, 120);
        push_u16_be(pkt, 5);      // rdlength=5 (invalid for type A)
        pkt.push_back(static_cast<std::byte>(5));
        pkt.push_back(static_cast<std::byte>(6));
        pkt.push_back(static_cast<std::byte>(7));
        pkt.push_back(static_cast<std::byte>(8));
        pkt.push_back(static_cast<std::byte>(0)); // 5th byte

        mock_executor ex;
        querier<MockPolicy> q{ex, 500ms};
        q.socket().enqueue(pkt);

        WHEN("async_query() is called")
        {
            q.async_query("good.local.", dns_type::a,
                [](std::error_code, std::vector<mdns_record_variant>) {});

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

// Note: Testing async_query() with an empty queue (no responses, silence timeout only)
// is not practical via querier's public API with MockTimer:
// MockTimer does not auto-fire; its fire() method is only accessible via
// the timer local variable, which is inaccessible from outside async_query().
// The silence-timeout path is covered by recv_loop_test.cpp directly.

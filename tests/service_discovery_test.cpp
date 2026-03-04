// tests/service_discovery_test.cpp
// service_discovery<MockPolicy> unit tests — Phase 7, Plan 07-03
// Tests the full discover() flow via MockPolicy.

#include "mdnspp/service_discovery.h"
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

using namespace mdnspp;
using namespace mdnspp::testing;
using namespace std::chrono_literals;

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

// Builds a mDNS response packet with one PTR record.
//   owner  — DNS name of the question (e.g. "_http._tcp.local.")
//   target — PTR rdata target name (e.g. "My Service._http._tcp.local.")
static std::vector<std::byte> make_ptr_response(std::string_view owner,
                                                 std::string_view target)
{
    std::vector<std::byte> pkt;

    // Header: id=0, flags=0x8400 (response|authoritative), qdcount=0,
    //         ancount=1, nscount=0, arcount=0
    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0001); // ancount
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    // Answer RR: name + type(PTR=12) + class(IN=1) + ttl + rdlength + rdata
    auto owner_enc  = encode_name(owner);
    auto target_enc = encode_name(target);

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 12);     // type PTR
    push_u16_be(pkt, 0x0001); // class IN
    push_u32_be(pkt, 4500);   // ttl
    push_u16_be(pkt, static_cast<uint16_t>(target_enc.size())); // rdlength
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    return pkt;
}

// Builds a mDNS response packet with one A record.
static std::vector<std::byte> make_a_response(std::string_view owner,
                                               uint8_t a, uint8_t b,
                                               uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0001); // ancount
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    auto owner_enc = encode_name(owner);
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

// Builds a mDNS response with two answer RRs: a PTR and an A record.
static std::vector<std::byte> make_multi_record_response()
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0002); // ancount = 2
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    // First RR: PTR
    auto owner_enc  = encode_name("_http._tcp.local.");
    auto target_enc = encode_name("MyService._http._tcp.local.");

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 12);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);
    push_u16_be(pkt, static_cast<uint16_t>(target_enc.size()));
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    // Second RR: A record for "myhost.local." -> 192.168.0.1
    auto host_enc = encode_name("myhost.local.");
    pkt.insert(pkt.end(), host_enc.begin(), host_enc.end());
    push_u16_be(pkt, 1);
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 4);
    pkt.push_back(static_cast<std::byte>(192));
    pkt.push_back(static_cast<std::byte>(168));
    pkt.push_back(static_cast<std::byte>(0));
    pkt.push_back(static_cast<std::byte>(1));

    return pkt;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

SCENARIO("service_discovery constructs and discovers", "[service_discovery][create]")
{
    GIVEN("a service_discovery instance with MockPolicy")
    {
        mock_executor ex;

        WHEN("constructed with 500ms silence timeout")
        {
            service_discovery<MockPolicy> sd{ex, 500ms};

            THEN("it is usable (socket is empty, results empty)")
            {
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}

SCENARIO("discover returns PTR record from mock socket", "[service_discovery][discover]")
{
    GIVEN("a service_discovery instance and a queued PTR response")
    {
        mock_executor ex;
        service_discovery<MockPolicy> sd{ex, 500ms};
        sd.socket().enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("discover() is called for _http._tcp.local.")
        {
            sd.discover("_http._tcp.local.");

            THEN("results() contains one record_ptr")
            {
                REQUIRE(sd.results().size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(sd.results()[0]));

                const auto &ptr = std::get<record_ptr>(sd.results()[0]);
                REQUIRE(ptr.ptr_name.find("MyService") != std::string::npos);
            }
        }
    }
}

SCENARIO("discover accumulates multiple records from a single frame",
         "[service_discovery][discover][multi]")
{
    GIVEN("a service_discovery instance and a multi-record response enqueued")
    {
        mock_executor ex;
        service_discovery<MockPolicy> sd{ex, 500ms};
        sd.socket().enqueue(make_multi_record_response());

        WHEN("discover() is called")
        {
            sd.discover("_http._tcp.local.");

            THEN("results() contains both records")
            {
                REQUIRE(sd.results().size() >= 2);
            }
        }
    }
}

SCENARIO("discover sends DNS PTR query to multicast address",
         "[service_discovery][discover][query]")
{
    GIVEN("a service_discovery instance with no enqueued responses")
    {
        mock_executor ex;
        service_discovery<MockPolicy> sd{ex, 500ms};

        WHEN("discover() is called for _http._tcp.local.")
        {
            sd.discover("_http._tcp.local.");

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

SCENARIO("discover skips malformed records and returns valid ones",
         "[service_discovery][discover][malformed]")
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
        auto owner_enc  = encode_name("_http._tcp.local.");
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
        push_u16_be(pkt, 1);      // type A
        push_u16_be(pkt, 0x0001);
        push_u32_be(pkt, 120);
        push_u16_be(pkt, 5);      // rdlength=5 (invalid for type A — parse::a checks length==4)
        pkt.push_back(static_cast<std::byte>(192));
        pkt.push_back(static_cast<std::byte>(168));
        pkt.push_back(static_cast<std::byte>(0));
        pkt.push_back(static_cast<std::byte>(1));
        pkt.push_back(static_cast<std::byte>(0)); // 5th byte — makes rdlength consistent

        mock_executor ex;
        service_discovery<MockPolicy> sd{ex, 500ms};
        sd.socket().enqueue(pkt);

        WHEN("discover() is called")
        {
            sd.discover("_http._tcp.local.");

            THEN("results() contains only the valid PTR record")
            {
                REQUIRE(sd.results().size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(sd.results()[0]));
                const auto &ptr = std::get<record_ptr>(sd.results()[0]);
                REQUIRE(ptr.ptr_name.find("Good") != std::string::npos);
            }
        }
    }
}

// Note: Testing discover() with an empty queue (no responses, silence timeout only)
// is not practical via service_discovery's public API with MockTimer:
// MockTimer does not auto-fire; its fire() method is only accessible via
// the timer local variable, which is inaccessible from outside discover().
// The silence-timeout path is covered by recv_loop_test.cpp directly.
// With AsioTimer (real integration test) this scenario works correctly.

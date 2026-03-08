// tests/observer_test.cpp

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>

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
    for(auto b : vals)
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
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>((v >> 8) & 0xFF)));
    buf.push_back(static_cast<std::byte>(static_cast<uint8_t>(v & 0xFF)));
}

// Encode a DNS name to wire label format (no compression).
static std::vector<std::byte> encode_name(std::string_view name)
{
    std::vector<std::byte> result;
    if(!name.empty() && name.back() == '.')
        name.remove_suffix(1);

    size_t pos = 0;
    while(pos < name.size())
    {
        size_t dot = name.find('.', pos);
        if(dot == std::string_view::npos)
            dot = name.size();
        size_t len = dot - pos;
        result.push_back(static_cast<std::byte>(static_cast<uint8_t>(len)));
        for(size_t i = pos; i < dot; ++i)
            result.push_back(static_cast<std::byte>(static_cast<uint8_t>(name[i])));
        pos = (dot < name.size()) ? dot + 1 : name.size();
    }
    result.push_back(static_cast<std::byte>(0x00)); // root label
    return result;
}

// Builds a complete mDNS response packet with one PTR record.
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

    auto owner_enc = encode_name(owner);
    auto target_enc = encode_name(target);

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 12);                                       // type PTR
    push_u16_be(pkt, 0x0001);                                   // class IN
    push_u32_be(pkt, 4500);                                     // ttl
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

SCENARIO("observer delivers DNS records from a single packet to the callback", "[observer][packet-delivery]")
{
    GIVEN("an observer with one PTR packet enqueued")
    {
        mock_executor ex;
        endpoint sender{"192.168.1.10", 5353};

        std::vector<mdns_record_variant> received_records;
        std::vector<endpoint> received_senders;

        basic_observer<MockPolicy> obs{
            ex, {},
            [&](const endpoint &ep, const mdns_record_variant &rec)
            {
                received_records.push_back(rec);
                received_senders.push_back(ep);
            }
        };

        obs.socket().enqueue(
            make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."), sender);

        WHEN("async_observe() is called")
        {
            obs.async_observe();

            THEN("the PTR record is delivered to the callback")
            {
                REQUIRE(received_records.size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(received_records[0]));
                const auto &ptr = std::get<record_ptr>(received_records[0]);
                REQUIRE(ptr.ptr_name.find("MyService") != std::string::npos);
            }

            AND_THEN("the sender endpoint is delivered alongside the record")
            {
                REQUIRE(received_senders.size() == 1);
                REQUIRE(received_senders[0] == sender);
            }
        }
    }
}

SCENARIO("observer delivers records from multiple packets", "[observer][multiple-packets]")
{
    GIVEN("an observer with two packets enqueued")
    {
        mock_executor ex;

        std::vector<mdns_record_variant> received_records;

        basic_observer<MockPolicy> obs{
            ex, {},
            [&](const endpoint &, const mdns_record_variant &rec)
            {
                received_records.push_back(rec);
            }
        };

        obs.socket().enqueue(make_ptr_response("_http._tcp.local.", "First._http._tcp.local."));
        obs.socket().enqueue(make_a_response("myhost.local.", 192, 168, 0, 1));

        WHEN("async_observe() is called")
        {
            obs.async_observe();

            THEN("records from all packets are delivered")
            {
                REQUIRE(received_records.size() == 2);
                REQUIRE(std::holds_alternative<record_ptr>(received_records[0]));
                REQUIRE(std::holds_alternative<record_a>(received_records[1]));
            }
        }
    }
}

SCENARIO("async_observe fires completion callback on stop", "[observer][async]")
{
    GIVEN("a fresh observer with no packets enqueued")
    {
        mock_executor ex;

        basic_observer<MockPolicy> obs{
            ex, {},
            [](const endpoint &, const mdns_record_variant &)
            {
            }
        };

        WHEN("async_observe() is called with a completion callback")
        {
            std::error_code received_ec;
            bool callback_fired = false;

            obs.async_observe([&](std::error_code ec)
            {
                callback_fired = true;
                received_ec = ec;
            });

            AND_WHEN("stop() is called")
            {
                obs.stop();
                ex.drain_posted();

                THEN("the completion callback fires with error_code{}")
                {
                    REQUIRE(callback_fired);
                    REQUIRE_FALSE(received_ec);
                }
            }
        }
    }
}

SCENARIO("stop() is idempotent — second call is a no-op", "[observer][stop-idempotent]")
{
    GIVEN("a started observer with no packets enqueued")
    {
        mock_executor ex;

        basic_observer<MockPolicy> obs{
            ex, {},
            [](const endpoint &, const mdns_record_variant &)
            {
            }
        };

        WHEN("async_observe() and then stop() are called twice")
        {
            obs.async_observe();

            THEN("the second stop() call does not crash or assert")
            {
                obs.stop();
                REQUIRE_NOTHROW(obs.stop()); // second call must be no-op
            }
        }
    }
}

SCENARIO("async_observe completion handler fires exactly once on double stop", "[observer][stop-idempotent][completion]")
{
    GIVEN("an observer with a completion callback")
    {
        mock_executor ex;
        int completion_count = 0;

        basic_observer<MockPolicy> obs{
            ex, {},
            [](const endpoint &, const mdns_record_variant &)
            {
            }
        };
        obs.async_observe([&](std::error_code) { ++completion_count; });

        WHEN("stop() is called twice")
        {
            obs.stop();
            obs.stop();
            ex.drain_posted();

            THEN("the completion callback fires exactly once")
            {
                REQUIRE(completion_count == 1);
            }
        }
    }
}

SCENARIO("observer can be created, started, and stopped without any packet delivery", "[observer][lifecycle]")
{
    GIVEN("a fresh observer with no packets enqueued")
    {
        mock_executor ex;
        int callback_count = 0;

        basic_observer<MockPolicy> obs{
            ex, {},
            [&](const endpoint &, const mdns_record_variant &) { ++callback_count; }
        };

        WHEN("async_observe() and stop() are called on the empty observer")
        {
            obs.async_observe();
            obs.stop();

            THEN("the record callback is never invoked")
            {
                REQUIRE(callback_count == 0);
            }
        }
    }
}

SCENARIO("stop() called from within the record callback does not deadlock", "[observer][callback-safe-stop]")
{
    GIVEN("an observer with one packet enqueued")
    {
        mock_executor ex;

        basic_observer<MockPolicy> *obs_ptr = nullptr;
        int callback_count = 0;

        basic_observer<MockPolicy> obs{
            ex, {},
            [&](const endpoint &, const mdns_record_variant &)
            {
                ++callback_count;
                // Call stop() from within the callback -- must not deadlock
                if(obs_ptr)
                    obs_ptr->stop();
            }
        };
        obs_ptr = &obs;

        obs.socket().enqueue(
            make_ptr_response("_http._tcp.local.", "Target._http._tcp.local."));

        WHEN("async_observe() is called (callback will call stop() inside itself)")
        {
            THEN("async_observe() returns without deadlocking and stop flag is set")
            {
                REQUIRE_NOTHROW(obs.async_observe());
                REQUIRE(callback_count >= 1);
            }
        }
    }
}

SCENARIO("observer non-throwing constructor sets ec on success", "[observer][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_observer<MockPolicy> is constructed with the ec overload")
        {
            basic_observer<MockPolicy> obs{
                ex, {},
                [](const endpoint &, const mdns_record_variant &)
                {
                },
                ec
            };

            THEN("ec is clear and the observer is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(obs.socket().queue_empty());
            }
        }
    }
}

SCENARIO("observer is move-constructible before async_observe", "[observer][move]")
{
    GIVEN("an observer constructed but not started")
    {
        mock_executor ex;
        basic_observer<MockPolicy> obs{
            ex, {},
            [](const endpoint &, const mdns_record_variant &)
            {
            }
        };

        WHEN("move-constructed into a new observer")
        {
            basic_observer<MockPolicy> moved{std::move(obs)};

            THEN("the moved-to observer is usable")
            {
                REQUIRE(moved.socket().queue_empty());
            }
        }
    }
}

SCENARIO("observer skips malformed packets without crashing", "[observer][malformed-packet]")
{
    GIVEN("an observer with a truncated (malformed) packet enqueued")
    {
        mock_executor ex;

        // Only 5 bytes — too short to be a valid DNS header (needs 12)
        std::vector<std::byte> malformed = bytes({0x00, 0x00, 0x00, 0x00, 0x00});

        int callback_count = 0;

        basic_observer<MockPolicy> obs{
            ex, {},
            [&](const endpoint &, const mdns_record_variant &) { ++callback_count; }
        };
        obs.socket().enqueue(malformed);

        WHEN("async_observe() is called with the malformed packet")
        {
            THEN("no crash occurs and no records are delivered")
            {
                REQUIRE_NOTHROW(obs.async_observe());
                REQUIRE(callback_count == 0);
            }
        }
    }
}

SCENARIO("basic_observer with socket_options", "[observer][socket_options]")
{
    GIVEN("a socket_options with a specific interface address")
    {
        mock_executor ex;
        socket_options opts{.interface_address = "10.0.0.1", .multicast_ttl = uint8_t{64}};

        WHEN("basic_observer<MockPolicy> is constructed with socket_options")
        {
            basic_observer<MockPolicy> obs{
                ex,
                opts,
                [](const endpoint &, const mdns_record_variant &) {}
            };

            THEN("the socket stores the options")
            {
                REQUIRE(obs.socket().options().interface_address == "10.0.0.1");
                REQUIRE(obs.socket().options().multicast_ttl == 64);
            }
        }
    }
}

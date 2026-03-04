// tests/service_server_test.cpp
// Phase 05, Plan 05-01, Task 2 — build_dns_response() tests
// Phase 05, Plan 05-02, Task 1+2 — service_server<S,T> BDD tests
// Verifies that build_dns_response() produces valid DNS wire-format responses
// for PTR, SRV, A, AAAA, and TXT query types, parseable by walk_dns_frame().
// Also verifies service_server<S,T> create/start/stop lifecycle and RFC 6762 timing.

#include "mdnspp/service_info.h"
#include "mdnspp/service_server.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/dns_wire.h"
#include "mdnspp/testing/mock_socket_policy.h"
#include "mdnspp/testing/mock_timer_policy.h"

#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <variant>
#include <optional>

using namespace mdnspp;
using namespace mdnspp::detail;
using namespace mdnspp::testing;

// ---------------------------------------------------------------------------
// Test fixture: a fully populated service_info
// ---------------------------------------------------------------------------

static service_info make_test_service()
{
    service_info info;
    info.service_name   = "MyService._http._tcp.local.";
    info.service_type   = "_http._tcp.local.";
    info.hostname       = "myhost.local.";
    info.port           = 8080;
    info.priority       = 0;
    info.weight         = 0;
    info.address_ipv4   = "192.168.1.10";
    info.address_ipv6   = std::nullopt;
    info.txt_records    = {service_txt{"path", "/api"}, service_txt{"ver", std::nullopt}};
    return info;
}

// ---------------------------------------------------------------------------
// Helper: parse all records from a build_dns_response() packet
// ---------------------------------------------------------------------------

static std::vector<mdns_record_variant> parse_response(const std::vector<std::byte> &pkt)
{
    std::vector<mdns_record_variant> records;
    walk_dns_frame(std::span<const std::byte>(pkt), endpoint{}, [&](mdns_record_variant rv) {
        records.push_back(std::move(rv));
    });
    return records;
}

// ---------------------------------------------------------------------------
// Helpers for service_server tests
// ---------------------------------------------------------------------------

static service_info make_test_info()
{
    service_info info;
    info.service_name = "MyService._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname     = "myhost.local.";
    info.port         = 8080;
    info.priority     = 0;
    info.weight       = 0;
    info.address_ipv4 = "192.168.1.10";
    info.txt_records  = {service_txt{"path", "/api"}};
    return info;
}

static std::vector<std::byte> make_ptr_query(std::string_view service_type)
{
    return build_dns_query(service_type, 12);
}

static std::vector<std::byte> make_a_query(std::string_view hostname)
{
    return build_dns_query(hostname, 1);
}

// ---------------------------------------------------------------------------
// SCENARIO: PTR response (qtype=12)
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response produces valid PTR response", "[build_dns_response][PTR]")
{
    GIVEN("a fully populated service_info")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=12 (PTR)")
        {
            auto pkt = build_dns_response(info, 12);

            THEN("the packet is non-empty")
            {
                REQUIRE_FALSE(pkt.empty());
            }

            THEN("the DNS header has flags=0x8400 (response, authoritative)")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t flags = (static_cast<uint16_t>(static_cast<uint8_t>(pkt[2])) << 8) |
                                  static_cast<uint16_t>(static_cast<uint8_t>(pkt[3]));
                REQUIRE(flags == 0x8400);
            }

            THEN("ancount >= 1 and arcount >= 1 (answer + additional)")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t ancount = (static_cast<uint16_t>(static_cast<uint8_t>(pkt[6])) << 8) |
                                    static_cast<uint16_t>(static_cast<uint8_t>(pkt[7]));
                uint16_t arcount = (static_cast<uint16_t>(static_cast<uint8_t>(pkt[10])) << 8) |
                                    static_cast<uint16_t>(static_cast<uint8_t>(pkt[11]));
                REQUIRE(ancount >= 1);
                REQUIRE(arcount >= 1);
            }

            THEN("walk_dns_frame parses a PTR record with the correct ptr_name")
            {
                auto records = parse_response(pkt);
                bool found_ptr = false;
                for (const auto &rv : records)
                {
                    if (std::holds_alternative<record_ptr>(rv))
                    {
                        const auto &ptr = std::get<record_ptr>(rv);
                        if (ptr.ptr_name.find("MyService") != std::string::npos)
                            found_ptr = true;
                    }
                }
                REQUIRE(found_ptr);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SCENARIO: PTR response includes additional SRV and A records
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response PTR response includes additional SRV and A records",
         "[build_dns_response][PTR][additional]")
{
    GIVEN("a service_info with both IPv4 address and TXT records")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=12 (PTR)")
        {
            auto pkt = build_dns_response(info, 12);

            THEN("walk_dns_frame yields PTR, SRV, and A records in the packet")
            {
                auto records = parse_response(pkt);

                bool has_ptr = false, has_srv = false, has_a = false;
                for (const auto &rv : records)
                {
                    if (std::holds_alternative<record_ptr>(rv))  has_ptr = true;
                    if (std::holds_alternative<record_srv>(rv))  has_srv = true;
                    if (std::holds_alternative<record_a>(rv))    has_a   = true;
                }
                REQUIRE(has_ptr);
                REQUIRE(has_srv);
                REQUIRE(has_a);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SCENARIO: A response (qtype=1)
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response produces valid A response", "[build_dns_response][A]")
{
    GIVEN("a service_info with address_ipv4 = \"192.168.1.10\"")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=1 (A)")
        {
            auto pkt = build_dns_response(info, 1);

            THEN("walk_dns_frame parses a record_a with address_string \"192.168.1.10\"")
            {
                auto records = parse_response(pkt);
                bool found = false;
                for (const auto &rv : records)
                {
                    if (std::holds_alternative<record_a>(rv))
                    {
                        const auto &a = std::get<record_a>(rv);
                        if (a.address_string == "192.168.1.10")
                            found = true;
                    }
                }
                REQUIRE(found);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SCENARIO: A response returns empty when no IPv4
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response returns empty for A when no IPv4 address",
         "[build_dns_response][A][no-ipv4]")
{
    GIVEN("a service_info without address_ipv4")
    {
        auto info = make_test_service();
        info.address_ipv4 = std::nullopt;

        WHEN("build_dns_response is called with qtype=1 (A)")
        {
            auto pkt = build_dns_response(info, 1);

            THEN("the returned vector is empty")
            {
                REQUIRE(pkt.empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SCENARIO: SRV response (qtype=33)
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response produces valid SRV response", "[build_dns_response][SRV]")
{
    GIVEN("a service_info with port=8080")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=33 (SRV)")
        {
            auto pkt = build_dns_response(info, 33);

            THEN("walk_dns_frame parses a record_srv with port 8080")
            {
                auto records = parse_response(pkt);
                bool found = false;
                for (const auto &rv : records)
                {
                    if (std::holds_alternative<record_srv>(rv))
                    {
                        const auto &srv = std::get<record_srv>(rv);
                        if (srv.port == 8080)
                            found = true;
                    }
                }
                REQUIRE(found);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SCENARIO: Unknown qtype returns empty
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response returns empty for unknown qtype",
         "[build_dns_response][unknown]")
{
    GIVEN("a service_info")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=255 (ANY — not in required set)")
        {
            // qtype=255 is ANY, handled separately; test an actually unknown type
            auto pkt = build_dns_response(info, 999);

            THEN("the returned vector is empty")
            {
                REQUIRE(pkt.empty());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SCENARIO: TXT response (qtype=16)
// ---------------------------------------------------------------------------

SCENARIO("build_dns_response produces valid TXT response", "[build_dns_response][TXT]")
{
    GIVEN("a service_info with txt_records = [{path, /api}, {ver}]")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=16 (TXT)")
        {
            auto pkt = build_dns_response(info, 16);

            THEN("the packet is non-empty")
            {
                REQUIRE_FALSE(pkt.empty());
            }

            THEN("walk_dns_frame parses a record_txt with at least one entry")
            {
                auto records = parse_response(pkt);
                bool found = false;
                for (const auto &rv : records)
                {
                    if (std::holds_alternative<record_txt>(rv))
                    {
                        const auto &txt = std::get<record_txt>(rv);
                        if (!txt.entries.empty())
                            found = true;
                    }
                }
                REQUIRE(found);
            }
        }
    }
}

// ===========================================================================
// service_server<S,T> BDD scenarios — Phase 05, Plan 05-02, Task 2
// ===========================================================================

SCENARIO("service_server::create returns valid instance", "[service_server][create]")
{
    GIVEN("MockSocketPolicy and MockTimerPolicy")
    {
        MockSocketPolicy socket;
        MockTimerPolicy response_timer;
        MockTimerPolicy recv_timer;

        WHEN("create() is called with a test service_info")
        {
            auto result = service_server<MockSocketPolicy, MockTimerPolicy>::create(
                std::move(socket), std::move(response_timer), std::move(recv_timer),
                make_test_info());

            THEN("the result has a value")
            {
                REQUIRE(result.has_value());
            }
        }
    }
}

SCENARIO("start and stop lifecycle", "[service_server][lifecycle]")
{
    GIVEN("a created service_server with no enqueued queries")
    {
        MockSocketPolicy socket;
        MockTimerPolicy response_timer;
        MockTimerPolicy recv_timer;
        auto result = service_server<MockSocketPolicy, MockTimerPolicy>::create(
            std::move(socket), std::move(response_timer), std::move(recv_timer),
            make_test_info());
        REQUIRE(result.has_value());
        auto &server = *result;

        WHEN("start() is called")
        {
            server.start();

            THEN("stop() can be called without error")
            {
                REQUIRE_NOTHROW(server.stop());

                AND_THEN("stop() can be called again (idempotent)")
                {
                    REQUIRE_NOTHROW(server.stop());
                }
            }
        }
    }
}

SCENARIO("service_server responds to PTR query after timer fires",
         "[service_server][ptr][response]")
{
    GIVEN("a service_server with a PTR query for _http._tcp.local. enqueued with sender endpoint")
    {
        MockSocketPolicy socket;
        MockTimerPolicy response_timer;
        MockTimerPolicy recv_timer;
        endpoint sender{"192.168.1.50", 5353};
        socket.enqueue(make_ptr_query("_http._tcp.local."), sender);

        auto result = service_server<MockSocketPolicy, MockTimerPolicy>::create(
            std::move(socket), std::move(response_timer), std::move(recv_timer),
            make_test_info());
        REQUIRE(result.has_value());
        auto &server = *result;

        WHEN("start() is called (MockSocketPolicy drains queue, fires on_query)")
        {
            server.start();

            AND_WHEN("the response timer is fired")
            {
                server.timer().fire();

                THEN("socket().sent_packets() is not empty")
                {
                    REQUIRE_FALSE(server.socket().sent_packets().empty());

                    AND_THEN("the response destination matches the sender endpoint")
                    {
                        REQUIRE(server.socket().sent_packets()[0].dest == sender);
                    }

                    AND_THEN("the response has DNS header flags 0x8400")
                    {
                        const auto &pkt = server.socket().sent_packets()[0].data;
                        REQUIRE(pkt.size() >= 4);
                        uint16_t flags =
                            (static_cast<uint16_t>(static_cast<uint8_t>(pkt[2])) << 8) |
                             static_cast<uint16_t>(static_cast<uint8_t>(pkt[3]));
                        REQUIRE(flags == 0x8400);
                    }
                }
            }
        }
    }
}

SCENARIO("response delay timer armed after query receipt",
         "[service_server][timer]")
{
    GIVEN("a service_server with a PTR query enqueued")
    {
        MockSocketPolicy socket;
        MockTimerPolicy response_timer;
        MockTimerPolicy recv_timer;
        socket.enqueue(make_ptr_query("_http._tcp.local."));

        auto result = service_server<MockSocketPolicy, MockTimerPolicy>::create(
            std::move(socket), std::move(response_timer), std::move(recv_timer),
            make_test_info());
        REQUIRE(result.has_value());
        auto &server = *result;

        WHEN("start() is called")
        {
            server.start();

            THEN("server.timer().has_pending() is true (response timer is armed)")
            {
                REQUIRE(server.timer().has_pending());

                AND_THEN("socket().sent_packets() is empty (response not yet sent)")
                {
                    REQUIRE(server.socket().sent_packets().empty());
                }
            }
        }
    }
}

SCENARIO("no response sent before timer fires",
         "[service_server][rfc6762][timing]")
{
    GIVEN("a service_server with a PTR query enqueued")
    {
        MockSocketPolicy socket;
        MockTimerPolicy response_timer;
        MockTimerPolicy recv_timer;
        socket.enqueue(make_ptr_query("_http._tcp.local."));

        auto result = service_server<MockSocketPolicy, MockTimerPolicy>::create(
            std::move(socket), std::move(response_timer), std::move(recv_timer),
            make_test_info());
        REQUIRE(result.has_value());
        auto &server = *result;

        WHEN("start() is called but the timer is NOT fired")
        {
            server.start();

            THEN("socket().sent_packets() is empty (no response until delay expires)")
            {
                REQUIRE(server.socket().sent_packets().empty());
            }
        }
    }
}

SCENARIO("stop before timer fires prevents response",
         "[service_server][stop][cancel]")
{
    GIVEN("a service_server with a PTR query enqueued")
    {
        MockSocketPolicy socket;
        MockTimerPolicy response_timer;
        MockTimerPolicy recv_timer;
        socket.enqueue(make_ptr_query("_http._tcp.local."));

        auto result = service_server<MockSocketPolicy, MockTimerPolicy>::create(
            std::move(socket), std::move(response_timer), std::move(recv_timer),
            make_test_info());
        REQUIRE(result.has_value());
        auto &server = *result;

        WHEN("start() is called then stop() is called before firing the timer")
        {
            server.start();
            server.stop();

            AND_WHEN("timer().fire() is called (simulating a late fire after cancel)")
            {
                server.timer().fire();

                THEN("socket().sent_packets() is empty (stop cancelled the timer)")
                {
                    REQUIRE(server.socket().sent_packets().empty());
                }
            }
        }
    }
}

SCENARIO("response to A query contains valid A record",
         "[service_server][A][response]")
{
    GIVEN("a service_server with an A query for myhost.local. enqueued")
    {
        MockSocketPolicy socket;
        MockTimerPolicy response_timer;
        MockTimerPolicy recv_timer;
        socket.enqueue(make_a_query("myhost.local."));

        auto result = service_server<MockSocketPolicy, MockTimerPolicy>::create(
            std::move(socket), std::move(response_timer), std::move(recv_timer),
            make_test_info());
        REQUIRE(result.has_value());
        auto &server = *result;

        WHEN("start() is called and the response timer fires")
        {
            server.start();
            server.timer().fire();

            THEN("socket().sent_packets() is not empty")
            {
                REQUIRE_FALSE(server.socket().sent_packets().empty());

                AND_THEN("walking the response with walk_dns_frame yields a record_a with address 192.168.1.10")
                {
                    const auto &pkt = server.socket().sent_packets()[0].data;
                    auto records = parse_response(pkt);
                    bool found = false;
                    for (const auto &rv : records)
                    {
                        if (std::holds_alternative<record_a>(rv))
                        {
                            const auto &a = std::get<record_a>(rv);
                            if (a.address_string == "192.168.1.10")
                                found = true;
                        }
                    }
                    REQUIRE(found);
                }
            }
        }
    }
}

SCENARIO("response sent to correct sender endpoint",
         "[service_server][endpoint]")
{
    GIVEN("a service_server with a PTR query enqueued from {10.0.0.1, 5353}")
    {
        MockSocketPolicy socket;
        MockTimerPolicy response_timer;
        MockTimerPolicy recv_timer;
        endpoint expected_dest{"10.0.0.1", 5353};
        socket.enqueue(make_ptr_query("_http._tcp.local."), expected_dest);

        auto result = service_server<MockSocketPolicy, MockTimerPolicy>::create(
            std::move(socket), std::move(response_timer), std::move(recv_timer),
            make_test_info());
        REQUIRE(result.has_value());
        auto &server = *result;

        WHEN("start() is called and the response timer fires")
        {
            server.start();
            server.timer().fire();

            THEN("socket().sent_packets()[0].dest == {10.0.0.1, 5353}")
            {
                REQUIRE_FALSE(server.socket().sent_packets().empty());
                REQUIRE(server.socket().sent_packets()[0].dest == expected_dest);
            }
        }
    }
}

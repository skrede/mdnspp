// tests/service_server_test.cpp
// Phase 05, Plan 05-01, Task 2 — build_dns_response() tests
// Verifies that build_dns_response() produces valid DNS wire-format responses
// for PTR, SRV, A, AAAA, and TXT query types, parseable by walk_dns_frame().

#include "mdnspp/service_info.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/dns_wire.h"

#include <catch2/catch_test_macros.hpp>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <string>
#include <variant>
#include <optional>

using namespace mdnspp;
using namespace mdnspp::detail;

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

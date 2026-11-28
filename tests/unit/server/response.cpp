#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>

namespace {

void ptr_response_sections(const std::vector<std::byte> &pkt)
{
    THEN("the DNS header has flags=0x8400 (response, authoritative)")
    {
        REQUIRE(pkt.size() >= 12);
        REQUIRE(read_u16_be(pkt, 2) == 0x8400);
    }

    THEN("ancount == 1 and arcount == 3 (PTR answer, SRV/TXT/A additionals)")
    {
        REQUIRE(pkt.size() >= 12);
        REQUIRE(read_u16_be(pkt, 6) == 1);
        REQUIRE(read_u16_be(pkt, 10) == 3);
    }

    THEN("walk_dns_frame parses a PTR record with the correct ptr_name")
    {
        REQUIRE(contains_record_where<record_ptr>(pkt, [](const record_ptr &ptr)
        {
            return ptr.ptr_name.find("MyService") != dns_name::npos;
        }));
    }
}

}

SCENARIO("build_dns_response produces valid PTR response", "[build_dns_response][PTR]")
{
    GIVEN("a fully populated service_info")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=12 (PTR)")
        {
            auto pkt = build_dns_response(info, dns_type::ptr, service_options{});

            THEN("the packet is non-empty")
            {
                REQUIRE_FALSE(pkt.empty());
            }

            ptr_response_sections(pkt);
        }
    }
}

SCENARIO("build_dns_response PTR response includes additional SRV and A records", "[build_dns_response][PTR][additional]")
{
    GIVEN("a service_info with both IPv4 address and TXT records")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=12 (PTR)")
        {
            auto pkt = build_dns_response(info, dns_type::ptr, service_options{});

            THEN("walk_dns_frame yields PTR, SRV, and A records in the packet")
            {
                REQUIRE(contains_record<record_ptr>(pkt));
                REQUIRE(contains_record<record_srv>(pkt));
                REQUIRE(contains_record<record_a>(pkt));
            }
        }
    }
}

SCENARIO("build_dns_response produces valid A response", "[build_dns_response][A]")
{
    GIVEN("a service_info with address_ipv4 = \"192.168.1.10\"")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=1 (A)")
        {
            auto pkt = build_dns_response(info, dns_type::a, service_options{});

            THEN("walk_dns_frame parses a record_a with address_string \"192.168.1.10\"")
            {
                REQUIRE(contains_record_where<record_a>(pkt, [](const record_a &a)
                {
                    return a.address_string == "192.168.1.10";
                }));
            }
        }
    }
}

SCENARIO("build_dns_response returns empty for A when no IPv4 address", "[build_dns_response][A][no-ipv4]")
{
    GIVEN("a service_info without address_ipv4")
    {
        auto info = make_test_service();
        info.address_ipv4 = std::nullopt;

        WHEN("build_dns_response is called with qtype=1 (A)")
        {
            auto pkt = build_dns_response(info, dns_type::a, service_options{});

            THEN("the returned vector is empty")
            {
                REQUIRE(pkt.empty());
            }
        }
    }
}

SCENARIO("build_dns_response produces valid SRV response", "[build_dns_response][SRV]")
{
    GIVEN("a service_info with port=8080")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=33 (SRV)")
        {
            auto pkt = build_dns_response(info, dns_type::srv, service_options{});

            THEN("walk_dns_frame parses a record_srv with port 8080")
            {
                REQUIRE(contains_record_where<record_srv>(pkt, [](const record_srv &srv) { return srv.port == 8080; }));
            }
        }
    }
}

SCENARIO("build_dns_response returns empty for unknown qtype", "[build_dns_response][unknown]")
{
    GIVEN("a service_info")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=255 (ANY -- not in required set)")
        {
            // ANY is handled separately, so the case uses a type no record builder knows.
            auto pkt = build_dns_response(info, static_cast<dns_type>(999), service_options{});

            THEN("the returned vector is empty")
            {
                REQUIRE(pkt.empty());
            }
        }
    }
}

SCENARIO("build_dns_response produces valid TXT response", "[build_dns_response][TXT]")
{
    GIVEN("a service_info with txt_records = [{path, /api}, {ver}]")
    {
        auto info = make_test_service();

        WHEN("build_dns_response is called with qtype=16 (TXT)")
        {
            auto pkt = build_dns_response(info, dns_type::txt, service_options{});

            THEN("the packet is non-empty")
            {
                REQUIRE_FALSE(pkt.empty());
            }

            THEN("walk_dns_frame parses a record_txt with at least one entry")
            {
                REQUIRE(contains_record_where<record_txt>(pkt, [](const record_txt &txt)
                {
                    return !txt.entries.empty();
                }));
            }
        }
    }
}

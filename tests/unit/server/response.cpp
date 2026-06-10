#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

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

            THEN("the DNS header has flags=0x8400 (response, authoritative)")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t flags = read_u16_be(pkt, 2);
                REQUIRE(flags == 0x8400);
            }

            THEN("ancount >= 1 and arcount >= 1 (answer + additional)")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t ancount = read_u16_be(pkt, 6);
                uint16_t arcount = read_u16_be(pkt, 10);
                REQUIRE(ancount >= 1);
                REQUIRE(arcount >= 1);
            }

            THEN("walk_dns_frame parses a PTR record with the correct ptr_name")
            {
                auto records = parse_response(pkt);
                bool found_ptr = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<record_ptr>(rv))
                    {
                        const auto &ptr = std::get<record_ptr>(rv);
                        if(ptr.ptr_name.find("MyService") != dns_name::npos)
                            found_ptr = true;
                    }
                }
                REQUIRE(found_ptr);
            }
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
                auto records = parse_response(pkt);

                bool has_ptr = false, has_srv = false, has_a = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<record_ptr>(rv)) has_ptr = true;
                    if(std::holds_alternative<record_srv>(rv)) has_srv = true;
                    if(std::holds_alternative<record_a>(rv)) has_a = true;
                }
                REQUIRE(has_ptr);
                REQUIRE(has_srv);
                REQUIRE(has_a);
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
                auto records = parse_response(pkt);
                bool found = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<record_a>(rv))
                    {
                        const auto &a = std::get<record_a>(rv);
                        if(a.address_string == "192.168.1.10")
                            found = true;
                    }
                }
                REQUIRE(found);
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
                auto records = parse_response(pkt);
                bool found = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<record_srv>(rv))
                    {
                        const auto &srv = std::get<record_srv>(rv);
                        if(srv.port == 8080)
                            found = true;
                    }
                }
                REQUIRE(found);
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
            // qtype=255 is ANY, handled separately; test an actually unknown type
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
                auto records = parse_response(pkt);
                bool found = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<record_txt>(rv))
                    {
                        const auto &txt = std::get<record_txt>(rv);
                        if(!txt.entries.empty())
                            found = true;
                    }
                }
                REQUIRE(found);
            }
        }
    }
}

#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <variant>
#include <string_view>

namespace {

bool any_ptr(const std::vector<sent_packet> &packets, std::string_view name_part, std::string_view target_part)
{
    for(const auto &sp : packets)
    {
        for(const auto &rv : parse_response(sp.data))
        {
            if(!std::holds_alternative<record_ptr>(rv))
                continue;
            const auto &ptr = std::get<record_ptr>(rv);
            if(ptr.name.find(name_part) != dns_name::npos && ptr.ptr_name.find(target_part) != dns_name::npos)
                return true;
        }
    }
    return false;
}

std::vector<std::byte> ptr_query(std::string_view name)
{
    return build_dns_query(name, dns_type::ptr, response_mode::multicast);
}

service_info with_printer_subtype()
{
    auto info = make_test_info();
    info.subtypes = {"_printer"};
    return info;
}

endpoint querier()
{
    return endpoint{"192.168.1.50", 5353};
}

}

SCENARIO("server responds to meta-query with PTR to service type", "[meta-query]")
{
    GIVEN("a live service server")
    {
        server_fixture f;
        f.go_live();
        f.clear_sent();

        WHEN("a PTR query for _services._dns-sd._udp.local. is injected")
        {
            f.inject(querier(), ptr_query("_services._dns-sd._udp.local."));

            THEN("a response is sent with PTR record pointing to service type")
            {
                // Sent at once, not deferred through aggregation.
                REQUIRE_FALSE(f.sent().empty());
                REQUIRE(any_ptr(f.sent(), "_services._dns-sd._udp", "_http._tcp"));
            }
        }
    }
}

SCENARIO("respond_to_meta_queries=false suppresses meta response", "[meta-query][disable]")
{
    GIVEN("a live service server with respond_to_meta_queries=false")
    {
        server_fixture f{make_test_info(), service_options{.respond_to_meta_queries = false}};
        f.go_live();
        f.clear_sent();

        WHEN("a PTR query for _services._dns-sd._udp.local. is injected")
        {
            f.inject(querier(), ptr_query("_services._dns-sd._udp.local."));

            THEN("no response is sent for the meta-query")
            {
                REQUIRE(f.sent().empty());
            }
        }
    }
}

SCENARIO("server responds to subtype PTR query", "[subtype]")
{
    GIVEN("a live service server with subtypes")
    {
        server_fixture f{with_printer_subtype()};
        f.go_live();
        f.clear_sent();

        WHEN("a PTR query for _printer._sub._http._tcp.local. is injected")
        {
            f.inject(querier(), ptr_query("_printer._sub._http._tcp.local."));

            THEN("a response is sent with PTR record pointing to service instance name")
            {
                REQUIRE_FALSE(f.sent().empty());
                REQUIRE(any_ptr(f.sent(), "_printer._sub._http._tcp", "MyService"));
            }
        }
    }
}

SCENARIO("announce_subtypes=true includes subtype PTR in announcements", "[subtype][announce]")
{
    GIVEN("a service server with subtypes and announce_subtypes=true")
    {
        server_fixture f{with_printer_subtype(), service_options{.announce_subtypes = true}};
        f.go_live();

        THEN("announcement packets include subtype PTR records")
        {
            REQUIRE(any_ptr(f.sent(), "_printer._sub._http._tcp", "MyService"));
        }
    }
}

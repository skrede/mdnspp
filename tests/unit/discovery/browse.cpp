#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <algorithm>
#include <string_view>

namespace {

void check_resolved_myservice(const resolved_service &svc)
{
    REQUIRE(svc.instance_name == "MyService._http._tcp.local");
    REQUIRE(svc.hostname == "myhost.local");
    REQUIRE(svc.port == 8080);
    REQUIRE(svc.ipv4_addresses.size() == 1);
    REQUIRE(svc.ipv4_addresses[0] == "192.168.1.1");
}

void resolved_sections(discovery_fixture &f)
{
    THEN("callback fires with one resolved_service")
    {
        check_completed(f.browsed);
        REQUIRE(f.browsed.results.size() == 1);
        check_resolved_myservice(f.browsed.results[0]);
    }

    AND_THEN("services() accessor matches callback data")
    {
        REQUIRE(f.sd.services().size() == 1);
        REQUIRE(f.sd.services()[0].instance_name == "MyService._http._tcp.local");
        REQUIRE(f.sd.services()[0].port == 8080);
    }

    AND_THEN("results() is also populated with raw records")
    {
        REQUIRE(f.sd.results().size() >= 2);
    }
}

// Delivery order is unspecified.
std::vector<resolved_service>::const_iterator find_instance(const std::vector<resolved_service> &services,
                                                            std::string_view label)
{
    return std::find_if(services.begin(), services.end(),
                        [label](const resolved_service &s) { return s.instance_name.find(label) != dns_name::npos; });
}

void check_alpha_and_beta(const std::vector<resolved_service> &services)
{
    REQUIRE(services.size() == 2);
    auto alpha_it = find_instance(services, "Alpha");
    auto beta_it = find_instance(services, "Beta");
    REQUIRE(alpha_it != services.end());
    REQUIRE(beta_it != services.end());
    REQUIRE(alpha_it->port == 80);
    REQUIRE(beta_it->port == 443);
}

}

SCENARIO("async_browse delivers fully resolved service after PTR+SRV+A response", "[service_discovery][browse]")
{
    GIVEN("a service_discovery and a full-service response (PTR+SRV+A)")
    {
        discovery_fixture f;
        f.enqueue(make_full_service_response("MyService._http._tcp.local.", "_http._tcp.local.", "myhost.local.", 8080,
                                             192, 168, 1, 1));

        WHEN("async_browse() is called and the silence timer fires")
        {
            f.browse(record_into(f.browsed));
            f.fire_silence();
            resolved_sections(f);
        }
    }
}

SCENARIO("async_browse delivers partial service when only PTR record arrives", "[service_discovery][browse][partial]")
{
    GIVEN("a service_discovery and a PTR-only response")
    {
        discovery_fixture f;
        f.enqueue(make_ptr_response("_http._tcp.local.", "PartialService._http._tcp.local."));

        WHEN("async_browse() is called and the silence timer fires")
        {
            f.browse(record_into(f.browsed));
            f.fire_silence();

            THEN("callback fires with one partial service (empty hostname/port/addresses)")
            {
                REQUIRE(f.browsed.fired);
                REQUIRE(f.browsed.results.size() == 1);
                const auto &svc = f.browsed.results[0];
                REQUIRE(svc.instance_name == "PartialService._http._tcp.local");
                REQUIRE(svc.hostname.empty());
                REQUIRE(svc.port == 0);
                REQUIRE(svc.ipv4_addresses.empty());
                REQUIRE(svc.ipv6_addresses.empty());
            }
        }
    }
}

SCENARIO("async_browse delivers multiple resolved services", "[service_discovery][browse][multi]")
{
    GIVEN("a service_discovery and two separate full-service response packets")
    {
        discovery_fixture f;
        f.enqueue(make_full_service_response("Alpha._http._tcp.local.", "_http._tcp.local.", "alpha.local.", 80,
                                             10, 0, 0, 1));
        f.enqueue(make_full_service_response("Beta._http._tcp.local.", "_http._tcp.local.", "beta.local.", 443,
                                             10, 0, 0, 2));

        WHEN("async_browse() is called and the silence timer fires")
        {
            f.browse(record_into(f.browsed));
            f.fire_silence();

            THEN("two resolved_service entries are delivered")
            {
                check_alpha_and_beta(f.browsed.results);
            }
        }
    }
}

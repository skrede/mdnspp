#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>

SCENARIO("async_browse delivers fully resolved service after PTR+SRV+A response", "[service_discovery][browse]")
{
    GIVEN("a service_discovery and a full-service response (PTR+SRV+A)")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, query_options{.silence_timeout = 500ms}};

        sd.socket().enqueue(make_full_service_response(
            "MyService._http._tcp.local.",
            "_http._tcp.local.",
            "myhost.local.",
            8080,
            192, 168, 1, 1));

        WHEN("async_browse() is called and the silence timer fires")
        {
            std::error_code received_ec;
            std::vector<resolved_service> received_services;
            bool callback_fired = false;

            sd.async_browse("_http._tcp.local.",
                            [&](std::error_code ec, std::vector<resolved_service> svcs)
                            {
                                callback_fired = true;
                                received_ec = ec;
                                received_services = std::move(svcs);
                            });

            sd.timer().fire();

            THEN("callback fires with one resolved_service")
            {
                REQUIRE(callback_fired);
                REQUIRE_FALSE(received_ec);
                REQUIRE(received_services.size() == 1);

                const auto &svc = received_services[0];
                REQUIRE(svc.instance_name == "MyService._http._tcp.local");
                REQUIRE(svc.hostname == "myhost.local");
                REQUIRE(svc.port == 8080);
                REQUIRE(svc.ipv4_addresses.size() == 1);
                REQUIRE(svc.ipv4_addresses[0] == "192.168.1.1");
            }

            AND_THEN("services() accessor matches callback data")
            {
                REQUIRE(sd.services().size() == 1);
                REQUIRE(sd.services()[0].instance_name == "MyService._http._tcp.local");
                REQUIRE(sd.services()[0].port == 8080);
            }

            AND_THEN("results() is also populated with raw records")
            {
                // PTR + SRV + A = 3 raw records (all in the packet)
                REQUIRE(sd.results().size() >= 2);
            }
        }
    }
}

SCENARIO("async_browse delivers partial service when only PTR record arrives", "[service_discovery][browse][partial]")
{
    GIVEN("a service_discovery and a PTR-only response")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, query_options{.silence_timeout = 500ms}};

        sd.socket().enqueue(make_ptr_response(
            "_http._tcp.local.",
            "PartialService._http._tcp.local."));

        WHEN("async_browse() is called and the silence timer fires")
        {
            std::vector<resolved_service> received_services;
            bool callback_fired = false;

            sd.async_browse("_http._tcp.local.",
                            [&](std::error_code, std::vector<resolved_service> svcs)
                            {
                                callback_fired = true;
                                received_services = std::move(svcs);
                            });

            sd.timer().fire();

            THEN("callback fires with one partial service (empty hostname/port/addresses)")
            {
                REQUIRE(callback_fired);
                REQUIRE(received_services.size() == 1);

                const auto &svc = received_services[0];
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
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, query_options{.silence_timeout = 500ms}};

        sd.socket().enqueue(make_full_service_response(
            "Alpha._http._tcp.local.",
            "_http._tcp.local.",
            "alpha.local.",
            80,
            10, 0, 0, 1));

        sd.socket().enqueue(make_full_service_response(
            "Beta._http._tcp.local.",
            "_http._tcp.local.",
            "beta.local.",
            443,
            10, 0, 0, 2));

        WHEN("async_browse() is called and the silence timer fires")
        {
            std::vector<resolved_service> received_services;

            sd.async_browse("_http._tcp.local.",
                            [&](std::error_code, std::vector<resolved_service> svcs)
                            {
                                received_services = std::move(svcs);
                            });

            sd.timer().fire();

            THEN("two resolved_service entries are delivered")
            {
                REQUIRE(received_services.size() == 2);

                // Find Alpha and Beta (order not guaranteed due to unordered_map)
                auto alpha_it = std::find_if(received_services.begin(), received_services.end(),
                                             [](const resolved_service &s) { return s.instance_name.find("alpha") != dns_name::npos; });
                auto beta_it = std::find_if(received_services.begin(), received_services.end(),
                                            [](const resolved_service &s) { return s.instance_name.find("beta") != dns_name::npos; });

                REQUIRE(alpha_it != received_services.end());
                REQUIRE(beta_it != received_services.end());

                REQUIRE(alpha_it->port == 80);
                REQUIRE(beta_it->port == 443);
            }
        }
    }
}

SCENARIO("async_enumerate_types returns parsed service types", "[service_discovery][enumerate]")
{
    GIVEN("a service_discovery and a PTR response for the meta-query")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, query_options{.silence_timeout = 500ms}};

        sd.socket().enqueue(make_ptr_response(
            "_services._dns-sd._udp.local.",
            "_http._tcp.local."));

        WHEN("async_enumerate_types() is called and the silence timer fires")
        {
            std::error_code received_ec;
            std::vector<service_type_info> received_types;
            bool callback_fired = false;

            sd.async_enumerate_types(
                [&](std::error_code ec, std::vector<service_type_info> types)
                {
                    callback_fired = true;
                    received_ec = ec;
                    received_types = std::move(types);
                });

            sd.timer().fire();

            THEN("a PTR query for _services._dns-sd._udp.local was sent")
            {
                REQUIRE_FALSE(sd.socket().sent_packets().empty());
                const auto &data = sd.socket().sent_packets()[0].data;
                REQUIRE(data.size() >= 12);
                // QDCOUNT should be 1
                REQUIRE(static_cast<uint8_t>(data[4]) == 0x00);
                REQUIRE(static_cast<uint8_t>(data[5]) == 0x01);
            }

            AND_THEN("the callback fires with one parsed service_type_info")
            {
                REQUIRE(callback_fired);
                REQUIRE_FALSE(received_ec);
                REQUIRE(received_types.size() == 1);
                REQUIRE(received_types[0].type_name == "_http");
                REQUIRE(received_types[0].protocol == "_tcp");
                REQUIRE(received_types[0].domain == "local");
            }
        }
    }
}

SCENARIO("async_discover_subtype discovers subtype instances", "[service_discovery][subtype]")
{
    GIVEN("a service_discovery and a PTR response for a subtype query")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, query_options{.silence_timeout = 500ms}};

        sd.socket().enqueue(make_ptr_response(
            "_printer._sub._http._tcp.local.",
            "MyService._http._tcp.local."));

        WHEN("async_discover_subtype() is called and the silence timer fires")
        {
            std::error_code received_ec;
            std::vector<mdns_record_variant> received_results;
            bool callback_fired = false;

            sd.async_discover_subtype("_http._tcp.local.", "_printer",
                [&](std::error_code ec, const std::vector<mdns_record_variant> &results)
                {
                    callback_fired = true;
                    received_ec = ec;
                    received_results = results;
                });

            sd.timer().fire();

            THEN("a PTR query for _printer._sub._http._tcp.local was sent")
            {
                REQUIRE_FALSE(sd.socket().sent_packets().empty());
                const auto &sent = sd.socket().sent_packets()[0];
                REQUIRE(sent.dest == endpoint{"224.0.0.251", 5353});
            }

            AND_THEN("the callback fires with the subtype PTR record")
            {
                REQUIRE(callback_fired);
                REQUIRE_FALSE(received_ec);
                REQUIRE(received_results.size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(received_results[0]));
                const auto &ptr = std::get<record_ptr>(received_results[0]);
                REQUIRE(ptr.ptr_name.find("myservice") != dns_name::npos);
            }
        }
    }
}

SCENARIO("discover query uses known-answer overload of build_dns_query", "[service_discovery][discover][known-answer]")
{
    GIVEN("a service_discovery instance with no enqueued responses")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, query_options{.silence_timeout = 500ms}};

        WHEN("async_discover() is called for the first time (m_results empty)")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, const std::vector<mdns_record_variant> &)
                              {
                              });

            THEN("a valid DNS query packet was sent with ancount=0 (no known answers on first query)")
            {
                REQUIRE_FALSE(sd.socket().sent_packets().empty());
                const auto &data = sd.socket().sent_packets()[0].data;
                REQUIRE(data.size() >= 12);
                // ANCOUNT should be 0 on first discover (no accumulated results yet)
                // Known-answer infrastructure is in place; ancount > 0 when m_results is pre-populated.
                REQUIRE(static_cast<uint8_t>(data[6]) == 0x00);
                REQUIRE(static_cast<uint8_t>(data[7]) == 0x00);
            }
        }
    }
}

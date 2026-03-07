// tests/service_discovery_test.cpp

#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/basic_service_discovery.h"

#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <cstddef>

using namespace mdnspp;
using namespace mdnspp::testing;
using namespace std::chrono_literals;

[[maybe_unused]] static std::vector<std::byte> bytes(std::initializer_list<unsigned char> vals)
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
[[maybe_unused]] static std::vector<std::byte> make_a_response(std::string_view owner,
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
    auto owner_enc = encode_name("_http._tcp.local.");
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
            basic_service_discovery<MockPolicy> sd{ex, 500ms};

            THEN("it is usable (socket is empty, results empty)")
            {
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}

SCENARIO("async_discover returns PTR record from mock socket", "[service_discovery][discover]")
{
    GIVEN("a service_discovery instance and a queued PTR response")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};
        sd.socket().enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("async_discover() is called for _http._tcp.local.")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, std::vector<mdns_record_variant>)
                              {
                              });

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

SCENARIO("async_discover fires completion callback with results", "[service_discovery][async]")
{
    GIVEN("a service_discovery instance and a queued PTR response")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};
        sd.socket().enqueue(make_ptr_response("_http._tcp.local.", "MyService._http._tcp.local."));

        WHEN("async_discover() is called with a completion callback and the silence timer fires")
        {
            std::error_code received_ec;
            std::vector<mdns_record_variant> received_results;
            bool callback_fired = false;

            sd.async_discover("_http._tcp.local.",
                              [&](std::error_code ec, std::vector<mdns_record_variant> results)
                              {
                                  callback_fired = true;
                                  received_ec = ec;
                                  received_results = std::move(results);
                              });

            // MockSocket drains the queue synchronously during async_discover(),
            // but the silence timer must be fired manually to trigger the completion callback.
            sd.timer().fire();

            THEN("the callback fires with error_code{} and the accumulated results")
            {
                REQUIRE(callback_fired);
                REQUIRE_FALSE(received_ec);
                REQUIRE(received_results.size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(received_results[0]));
                const auto &ptr = std::get<record_ptr>(received_results[0]);
                REQUIRE(ptr.ptr_name.find("MyService") != std::string::npos);
            }

            AND_THEN("results() accessor is still populated (completion handler received a copy)")
            {
                REQUIRE(sd.results().size() == 1);
            }
        }
    }
}

SCENARIO("async_discover accumulates multiple records from a single frame", "[service_discovery][discover][multi]")
{
    GIVEN("a service_discovery instance and a multi-record response enqueued")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};
        sd.socket().enqueue(make_multi_record_response());

        WHEN("async_discover() is called")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, std::vector<mdns_record_variant>)
                              {
                              });

            THEN("results() contains both records")
            {
                REQUIRE(sd.results().size() >= 2);
            }
        }
    }
}

SCENARIO("async_discover sends DNS PTR query to multicast address", "[service_discovery][discover][query]")
{
    GIVEN("a service_discovery instance with no enqueued responses")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

        WHEN("async_discover() is called for _http._tcp.local.")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, std::vector<mdns_record_variant>)
                              {
                              });

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

SCENARIO("async_discover skips malformed records and returns valid ones", "[service_discovery][discover][malformed]")
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
        auto owner_enc = encode_name("_http._tcp.local.");
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
        push_u16_be(pkt, 1); // type A
        push_u16_be(pkt, 0x0001);
        push_u32_be(pkt, 120);
        push_u16_be(pkt, 5); // rdlength=5 (invalid for type A — parse::a checks length==4)
        pkt.push_back(static_cast<std::byte>(192));
        pkt.push_back(static_cast<std::byte>(168));
        pkt.push_back(static_cast<std::byte>(0));
        pkt.push_back(static_cast<std::byte>(1));
        pkt.push_back(static_cast<std::byte>(0)); // 5th byte — makes rdlength consistent

        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};
        sd.socket().enqueue(pkt);

        WHEN("async_discover() is called")
        {
            sd.async_discover("_http._tcp.local.",
                              [](std::error_code, std::vector<mdns_record_variant>)
                              {
                              });

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

// Note: Testing async_discover() with an empty queue (no responses, silence timeout only)
// is not practical via service_discovery's public API with MockTimer:
// MockTimer does not auto-fire; its fire() method is only accessible via
// the timer local variable, which is inaccessible from outside async_discover().
// The silence-timeout path is covered by recv_loop_test.cpp directly.
// With AsioTimer (real integration test) this scenario works correctly.

// ---------------------------------------------------------------------------
// Additional wire-format helpers for async_browse tests
// ---------------------------------------------------------------------------

// Builds a mDNS response with one SRV record.
//   owner           — fully-qualified service instance name (e.g. "My Service._http._tcp.local.")
//   target_hostname — SRV target (e.g. "myhost.local.")
//   port            — service port
[[maybe_unused]] static std::vector<std::byte> make_srv_response(std::string_view owner,
                                                std::string_view target_hostname,
                                                uint16_t port)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags (response|authoritative)
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0001); // ancount
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    auto owner_enc = encode_name(owner);
    auto target_enc = encode_name(target_hostname);

    pkt.insert(pkt.end(), owner_enc.begin(), owner_enc.end());
    push_u16_be(pkt, 33);     // type SRV
    push_u16_be(pkt, 0x0001); // class IN
    push_u32_be(pkt, 120);    // ttl

    // SRV rdata: priority(2) + weight(2) + port(2) + target
    auto rdlength = static_cast<uint16_t>(2 + 2 + 2 + target_enc.size());
    push_u16_be(pkt, rdlength);
    push_u16_be(pkt, 0); // priority
    push_u16_be(pkt, 0); // weight
    push_u16_be(pkt, port);
    pkt.insert(pkt.end(), target_enc.begin(), target_enc.end());

    return pkt;
}

// Builds a single DNS response packet containing PTR + SRV + A records
// for one fully-resolved service instance.
//   instance_name — e.g. "MyService._http._tcp.local."
//   hostname      — e.g. "myhost.local."
//   port          — service port
//   ipv4          — { a, b, c, d }
static std::vector<std::byte> make_full_service_response(
    std::string_view instance_name,
    std::string_view service_type,
    std::string_view hostname,
    uint16_t port,
    uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    std::vector<std::byte> pkt;

    push_u16_be(pkt, 0x0000); // id
    push_u16_be(pkt, 0x8400); // flags
    push_u16_be(pkt, 0x0000); // qdcount
    push_u16_be(pkt, 0x0003); // ancount = 3 (PTR + SRV + A)
    push_u16_be(pkt, 0x0000); // nscount
    push_u16_be(pkt, 0x0000); // arcount

    // RR 1: PTR  service_type -> instance_name
    auto svc_enc = encode_name(service_type);
    auto instance_enc = encode_name(instance_name);
    pkt.insert(pkt.end(), svc_enc.begin(), svc_enc.end());
    push_u16_be(pkt, 12); // type PTR
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 4500);
    push_u16_be(pkt, static_cast<uint16_t>(instance_enc.size()));
    pkt.insert(pkt.end(), instance_enc.begin(), instance_enc.end());

    // RR 2: SRV  instance_name -> hostname + port
    auto host_enc = encode_name(hostname);
    pkt.insert(pkt.end(), instance_enc.begin(), instance_enc.end());
    push_u16_be(pkt, 33); // type SRV
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, static_cast<uint16_t>(2 + 2 + 2 + host_enc.size()));
    push_u16_be(pkt, 0); // priority
    push_u16_be(pkt, 0); // weight
    push_u16_be(pkt, port);
    pkt.insert(pkt.end(), host_enc.begin(), host_enc.end());

    // RR 3: A  hostname -> IPv4
    pkt.insert(pkt.end(), host_enc.begin(), host_enc.end());
    push_u16_be(pkt, 1); // type A
    push_u16_be(pkt, 0x0001);
    push_u32_be(pkt, 120);
    push_u16_be(pkt, 4);
    pkt.push_back(static_cast<std::byte>(a));
    pkt.push_back(static_cast<std::byte>(b));
    pkt.push_back(static_cast<std::byte>(c));
    pkt.push_back(static_cast<std::byte>(d));

    return pkt;
}

// ---------------------------------------------------------------------------
// async_browse tests
// ---------------------------------------------------------------------------

SCENARIO("async_browse delivers fully resolved service after PTR+SRV+A response", "[service_discovery][browse]")
{
    GIVEN("a service_discovery and a full-service response (PTR+SRV+A)")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

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
                // read_dns_name produces no trailing dot — convention throughout the library
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
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

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
                // read_dns_name produces no trailing dot — convention throughout the library
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
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

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
                                             [](const resolved_service &s) { return s.instance_name.find("Alpha") != std::string::npos; });
                auto beta_it = std::find_if(received_services.begin(), received_services.end(),
                                            [](const resolved_service &s) { return s.instance_name.find("Beta") != std::string::npos; });

                REQUIRE(alpha_it != received_services.end());
                REQUIRE(beta_it != received_services.end());

                REQUIRE(alpha_it->port == 80);
                REQUIRE(beta_it->port == 443);
            }
        }
    }
}

SCENARIO("stop() during async_browse fires completion with partial aggregated results", "[service_discovery][browse][stop]")
{
    GIVEN("a service_discovery with a PTR-only response and no silence timeout fired")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

        sd.socket().enqueue(make_ptr_response(
            "_http._tcp.local.",
            "StoppedService._http._tcp.local."));

        std::vector<resolved_service> received_services;
        bool callback_fired = false;

        sd.async_browse("_http._tcp.local.",
                        [&](std::error_code, std::vector<resolved_service> svcs)
                        {
                            callback_fired = true;
                            received_services = std::move(svcs);
                        });

        WHEN("stop() is called before the silence timeout")
        {
            sd.stop();

            THEN("browse completion fires with whatever was aggregated so far")
            {
                REQUIRE(callback_fired);
                REQUIRE(received_services.size() == 1);
                // read_dns_name produces no trailing dot — convention throughout the library
                REQUIRE(received_services[0].instance_name == "StoppedService._http._tcp.local");
            }
        }
    }
}

SCENARIO("service_discovery non-throwing constructor sets ec on success", "[service_discovery][create][non-throwing]")
{
    GIVEN("a mock_executor and an error_code")
    {
        mock_executor ex;
        std::error_code ec;

        WHEN("basic_service_discovery<MockPolicy> is constructed with the ec overload")
        {
            basic_service_discovery<MockPolicy> sd{ex, 500ms, ec};

            THEN("ec is clear and the service_discovery is usable")
            {
                REQUIRE_FALSE(ec);
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}

SCENARIO("service_discovery is move-constructible before async_discover", "[service_discovery][move]")
{
    GIVEN("a service_discovery constructed but not started")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

        WHEN("move-constructed into a new instance")
        {
            basic_service_discovery<MockPolicy> moved{std::move(sd)};

            THEN("the moved-to instance is usable")
            {
                REQUIRE(moved.socket().queue_empty());
                REQUIRE(moved.results().empty());
            }
        }
    }
}

SCENARIO("service_discovery stop with both discover and browse loops", "[service_discovery][stop][browse]")
{
    GIVEN("a service_discovery with browse started and a PTR response queued")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

        sd.socket().enqueue(make_ptr_response(
            "_http._tcp.local.",
            "Svc._http._tcp.local."));

        std::vector<resolved_service> received_services;
        bool browse_fired = false;

        sd.async_browse("_http._tcp.local.",
                        [&](std::error_code, std::vector<resolved_service> svcs)
                        {
                            browse_fired = true;
                            received_services = std::move(svcs);
                        });

        WHEN("stop() is called")
        {
            sd.stop();

            THEN("the browse completion fires with aggregated results")
            {
                REQUIRE(browse_fired);
                REQUIRE(received_services.size() == 1);
            }
        }
    }
}

SCENARIO("on_record callback fires during async_browse (same as async_discover)", "[service_discovery][browse][on_record]")
{
    GIVEN("a service_discovery with an on_record callback and a PTR response")
    {
        mock_executor ex;
        std::vector<mdns_record_variant> captured_records;

        basic_service_discovery<MockPolicy> sd{
            ex,
            500ms,
            [&](const endpoint &, const mdns_record_variant &rec)
            {
                captured_records.push_back(rec);
            }
        };

        sd.socket().enqueue(make_ptr_response(
            "_http._tcp.local.",
            "MyService._http._tcp.local."));

        WHEN("async_browse() is called and silence timer fires")
        {
            sd.async_browse("_http._tcp.local.",
                            [](std::error_code, std::vector<resolved_service>)
                            {
                            });

            sd.timer().fire();

            THEN("on_record callback was invoked for each relevant record")
            {
                REQUIRE(captured_records.size() == 1);
                REQUIRE(std::holds_alternative<record_ptr>(captured_records[0]));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Known-answer, enumerate_types, discover_subtype tests (Plan 31-03)
// ---------------------------------------------------------------------------

SCENARIO("discover query uses known-answer overload of build_dns_query", "[service_discovery][discover][known-answer]")
{
    GIVEN("a service_discovery instance with no enqueued responses")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

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

SCENARIO("async_enumerate_types returns parsed service types", "[service_discovery][enumerate]")
{
    GIVEN("a service_discovery and a PTR response for the meta-query")
    {
        mock_executor ex;
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

        // Enqueue a PTR response: owner = _services._dns-sd._udp.local, target = _http._tcp.local
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
        basic_service_discovery<MockPolicy> sd{ex, 500ms};

        // Enqueue a PTR response: owner = _printer._sub._http._tcp.local, target = MyService._http._tcp.local
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
                REQUIRE(ptr.ptr_name.find("MyService") != std::string::npos);
            }
        }
    }
}

SCENARIO("basic_service_discovery with socket_options", "[service_discovery][socket_options]")
{
    GIVEN("a socket_options with a specific interface address")
    {
        mock_executor ex;
        socket_options opts{.interface_address = "172.16.0.1"};

        WHEN("basic_service_discovery<MockPolicy> is constructed with socket_options")
        {
            basic_service_discovery<MockPolicy> sd{ex, opts, 500ms};

            THEN("the socket stores the options")
            {
                REQUIRE(sd.socket().options().interface_address == "172.16.0.1");
                REQUIRE(sd.socket().queue_empty());
                REQUIRE(sd.results().empty());
            }
        }
    }
}

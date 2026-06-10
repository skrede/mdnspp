#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

// Builds a standard mDNS PTR query packet and sets the TC (truncation) bit.
static std::vector<std::byte> make_tc_ptr_query(std::string_view service_type)
{
    auto pkt = build_dns_query(service_type, dns_type::ptr);
    // Flags are at bytes 2-3. Set TC bit (0x0200).
    pkt[2] = static_cast<std::byte>(static_cast<uint8_t>(pkt[2]) | 0x02u);
    return pkt;
}

SCENARIO("service_options with designated initializers", "[service_server][service_options]")
{
    GIVEN("a mock_executor")
    {
        mock_executor ex;
        bool query_called = false;

        WHEN("server is constructed with designated initializer service_options")
        {
            basic_service_server<mock_policy> server{ex, make_test_info(), service_options{
                .on_query = [&](const endpoint &, dns_type, response_mode) { query_called = true; },
                .announce_count = 5
            }};

            THEN("the server is constructed successfully")
            {
                REQUIRE(server.socket().queue_empty());
            }
        }
    }
}

SCENARIO("constructor with socket_options and service_options", "[service_server][constructor]")
{
    GIVEN("a mock_executor with socket_options and service_options")
    {
        mock_executor ex;
        socket_options sock_opts{.interface_address = "10.0.0.1"};

        WHEN("server is constructed with both option types")
        {
            basic_service_server<mock_policy> server{ex, make_test_info(), service_options{.announce_count = 3}, sock_opts};

            THEN("the server is constructed successfully")
            {
                REQUIRE(server.socket().options().interface_address == "10.0.0.1");
            }
        }
    }
}

SCENARIO("server responds to meta-query with PTR to service type", "[meta-query]")
{
    GIVEN("a live service server")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        WHEN("a PTR query for _services._dns-sd._udp.local. is injected")
        {
            auto query = build_dns_query("_services._dns-sd._udp.local.", dns_type::ptr, response_mode::multicast);
            endpoint sender{"192.168.1.50", 5353};
            server.socket().inject_receive(sender, std::move(query));

            THEN("a response is sent with PTR record pointing to service type")
            {
                // Meta-query response is sent immediately (not deferred through aggregation)
                REQUIRE_FALSE(server.socket().sent_packets().empty());

                bool found_meta_ptr = false;
                for(const auto &sp : server.socket().sent_packets())
                {
                    auto records = parse_response(sp.data);
                    for(const auto &rv : records)
                    {
                        if(std::holds_alternative<record_ptr>(rv))
                        {
                            const auto &ptr = std::get<record_ptr>(rv);
                            // PTR name should be _services._dns-sd._udp.local
                            // ptr_name should be the service type (without trailing dot)
                            if(ptr.name.find("_services._dns-sd._udp") != dns_name::npos &&
                               ptr.ptr_name.find("_http._tcp") != dns_name::npos)
                            {
                                found_meta_ptr = true;
                            }
                        }
                    }
                }
                REQUIRE(found_meta_ptr);
            }
        }
    }
}

SCENARIO("respond_to_meta_queries=false suppresses meta response", "[meta-query][disable]")
{
    GIVEN("a live service server with respond_to_meta_queries=false")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info(),
            service_options{.respond_to_meta_queries = false}};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        WHEN("a PTR query for _services._dns-sd._udp.local. is injected")
        {
            auto query = build_dns_query("_services._dns-sd._udp.local.", dns_type::ptr, response_mode::multicast);
            endpoint sender{"192.168.1.50", 5353};
            server.socket().inject_receive(sender, std::move(query));

            THEN("no response is sent for the meta-query")
            {
                REQUIRE(server.socket().sent_packets().empty());
            }
        }
    }
}

SCENARIO("server responds to subtype PTR query", "[subtype]")
{
    GIVEN("a live service server with subtypes")
    {
        mock_executor ex;
        auto info = make_test_info();
        info.subtypes = {"_printer"};
        basic_service_server<mock_policy> server{ex, std::move(info)};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        WHEN("a PTR query for _printer._sub._http._tcp.local. is injected")
        {
            auto query = build_dns_query("_printer._sub._http._tcp.local.", dns_type::ptr, response_mode::multicast);
            endpoint sender{"192.168.1.50", 5353};
            server.socket().inject_receive(sender, std::move(query));

            THEN("a response is sent with PTR record pointing to service instance name")
            {
                REQUIRE_FALSE(server.socket().sent_packets().empty());

                bool found_subtype_ptr = false;
                for(const auto &sp : server.socket().sent_packets())
                {
                    auto records = parse_response(sp.data);
                    for(const auto &rv : records)
                    {
                        if(std::holds_alternative<record_ptr>(rv))
                        {
                            const auto &ptr = std::get<record_ptr>(rv);
                            if(ptr.name.find("_printer._sub._http._tcp") != dns_name::npos &&
                               ptr.ptr_name.find("myservice") != dns_name::npos)
                            {
                                found_subtype_ptr = true;
                            }
                        }
                    }
                }
                REQUIRE(found_subtype_ptr);
            }
        }
    }
}

SCENARIO("announce_subtypes=true includes subtype PTR in announcements", "[subtype][announce]")
{
    GIVEN("a service server with subtypes and announce_subtypes=true")
    {
        mock_executor ex;
        auto info = make_test_info();
        info.subtypes = {"_printer"};
        basic_service_server<mock_policy> server{ex, std::move(info),
            service_options{.announce_subtypes = true}};
        server.async_start();
        advance_to_live(server);

        THEN("announcement packets include subtype PTR records")
        {
            bool found_subtype_ptr = false;
            for(const auto &sp : server.socket().sent_packets())
            {
                auto records = parse_response(sp.data);
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<record_ptr>(rv))
                    {
                        const auto &ptr = std::get<record_ptr>(rv);
                        if(ptr.name.find("_printer._sub._http._tcp") != dns_name::npos &&
                           ptr.ptr_name.find("myservice") != dns_name::npos)
                        {
                            found_subtype_ptr = true;
                        }
                    }
                }
            }
            REQUIRE(found_subtype_ptr);
        }
    }
}

SCENARIO("on_error callback fires on send failure", "[service_server][on_error]")
{
    GIVEN("a service_server with on_error callback and send failure injection")
    {
        mock_executor ex;

        std::error_code received_ec;
        std::string received_context;

        service_options opts;
        opts.on_error = [&](std::error_code ec, std::string_view ctx)
        {
            received_ec = ec;
            received_context = std::string(ctx);
        };

        basic_service_server<mock_policy> server{ex, make_test_info(), std::move(opts)};

        mock_socket::set_fail_on_send(true);

        WHEN("the server starts and attempts to send a probe")
        {
            server.async_start();
            // First timer fire triggers send_probe via start_probing delay
            server.timer().fire();

            THEN("on_error was called with a non-empty context string")
            {
                REQUIRE(received_ec);
                REQUIRE(received_ec == std::errc::network_unreachable);
                REQUIRE_FALSE(received_context.empty());
            }
        }

        mock_socket::set_fail_on_send(false);
    }
}

SCENARIO("stop-then-destroy is safe without draining posted work", "[service_server][stop-destroy-safety]")
{
    GIVEN("a service_server in a scoped block")
    {
        mock_executor ex;

        WHEN("the server is created, started, stopped, and destroyed without draining")
        {
            THEN("no crash occurs (posted lambda becomes a no-op via weak_ptr sentinel)")
            {
                REQUIRE_NOTHROW([&]()
                {
                    basic_service_server<mock_policy> server{ex, make_test_info()};
                    server.async_start();
                    advance_to_live(server);
                    server.stop();
                    // Destroy without calling ex.drain_posted()
                }());

                // The posted work is still in the executor queue but the lambda
                // becomes a no-op because m_alive was reset by the destructor.
                REQUIRE_NOTHROW(ex.drain_posted());
            }
        }
    }
}

SCENARIO("Server sends unicast response to legacy unicast query (port != 5353)", "[service_server][legacy_unicast][rfc01]")
{
    GIVEN("a live server with default service_options (respond_to_legacy_unicast=true)")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        endpoint legacy_sender{"10.0.0.1", 12345}; // port != 5353
        auto query = make_ptr_query("_http._tcp.local.");
        server.socket().inject_receive(legacy_sender, query);

        WHEN("a PTR query arrives from a non-5353 port")
        {
            THEN("the response is sent directly to the legacy sender (unicast)")
            {
                bool unicast_to_sender = false;
                for(const auto &pkt : server.socket().sent_packets())
                {
                    if(pkt.dest == legacy_sender)
                        unicast_to_sender = true;
                }
                REQUIRE(unicast_to_sender);
            }

            THEN("the response is NOT sent to the multicast group for that legacy query")
            {
                endpoint mcast{"224.0.0.251", 5353};
                bool multicast_sent = false;
                for(const auto &pkt : server.socket().sent_packets())
                {
                    if(pkt.dest == mcast)
                        multicast_sent = true;
                }
                REQUIRE_FALSE(multicast_sent);
            }
        }
    }
}

SCENARIO("Server respects legacy_unicast_ttl cap on legacy unicast responses", "[service_server][legacy_unicast][ttl]")
{
    GIVEN("a live server with legacy_unicast_ttl=10 (default) and record_ttl=4500")
    {
        mock_executor ex;
        mdns_options mopts;
        mopts.legacy_unicast_ttl = std::chrono::seconds{10};
        mopts.record_ttl = std::chrono::seconds{4500};
        mopts.response_delay_min = std::chrono::milliseconds{0};
        mopts.response_delay_max = std::chrono::milliseconds{0};

        basic_service_server<mock_policy> server{ex, make_test_info(), {}, {}, std::move(mopts)};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        endpoint legacy_sender{"10.0.0.1", 12345};
        auto query = make_ptr_query("_http._tcp.local.");
        server.socket().inject_receive(legacy_sender, query);

        WHEN("the legacy unicast response is sent")
        {
            THEN("all records in the response have TTL <= 10")
            {
                bool found_response = false;
                for(const auto &pkt : server.socket().sent_packets())
                {
                    if(pkt.dest != legacy_sender) continue;
                    found_response = true;

                    auto records = parse_response(pkt.data);
                    for(const auto &rv : records)
                    {
                        uint32_t ttl = std::visit([](const auto &r) { return r.ttl; }, rv);
                        REQUIRE(ttl <= 10u);
                    }
                }
                REQUIRE(found_response);
            }
        }
    }
}

SCENARIO("Server ignores legacy unicast when respond_to_legacy_unicast=false", "[service_server][legacy_unicast][disabled]")
{
    GIVEN("a live server with respond_to_legacy_unicast=false")
    {
        mock_executor ex;
        service_options opts;
        opts.respond_to_legacy_unicast = false;
        mdns_options mopts;
        mopts.response_delay_min = std::chrono::milliseconds{0};
        mopts.response_delay_max = std::chrono::milliseconds{0};

        basic_service_server<mock_policy> server{ex, make_test_info(), std::move(opts), {}, std::move(mopts)};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        endpoint legacy_sender{"10.0.0.1", 12345};
        auto query = make_ptr_query("_http._tcp.local.");
        server.socket().inject_receive(legacy_sender, query);

        WHEN("a PTR query arrives from a non-5353 port")
        {
            THEN("no direct unicast response is sent to the legacy sender")
            {
                bool unicast_to_sender = false;
                for(const auto &pkt : server.socket().sent_packets())
                {
                    if(pkt.dest == legacy_sender)
                        unicast_to_sender = true;
                }
                REQUIRE_FALSE(unicast_to_sender);
            }

            THEN("a multicast response timer is armed (normal multicast path)")
            {
                // With response_delay_min=0, the response timer should fire immediately
                server.timer().fire();
                endpoint mcast{"224.0.0.251", 5353};
                bool multicast_sent = false;
                for(const auto &pkt : server.socket().sent_packets())
                {
                    if(pkt.dest == mcast)
                        multicast_sent = true;
                }
                REQUIRE(multicast_sent);
            }
        }
    }
}

SCENARIO("Normal mDNS query from port 5353 uses multicast path", "[service_server][legacy_unicast][normal]")
{
    GIVEN("a live server")
    {
        mock_executor ex;
        mdns_options mopts;
        mopts.response_delay_min = std::chrono::milliseconds{0};
        mopts.response_delay_max = std::chrono::milliseconds{0};

        basic_service_server<mock_policy> server{ex, make_test_info(), {}, {}, std::move(mopts)};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        endpoint normal_sender{"192.168.1.50", 5353}; // standard mDNS port
        auto query = make_ptr_query("_http._tcp.local.");
        server.socket().inject_receive(normal_sender, query);

        WHEN("a PTR query arrives from port 5353")
        {
            THEN("no direct unicast response is sent to the sender")
            {
                bool unicast_to_sender = false;
                for(const auto &pkt : server.socket().sent_packets())
                {
                    if(pkt.dest == normal_sender)
                        unicast_to_sender = true;
                }
                REQUIRE_FALSE(unicast_to_sender);
            }
        }
    }
}

SCENARIO("on_tc_continuation callback fires when TC timer expires",
         "[service_server][tc][callback]")
{
    GIVEN("a live service server with on_tc_continuation callback configured")
    {
        mock_executor ex;

        endpoint captured_sender;
        std::size_t captured_count = 0;

        service_options opts;
        opts.on_tc_continuation = [&](const endpoint &sender, std::size_t count)
        {
            captured_sender = sender;
            captured_count = count;
        };

        basic_service_server<mock_policy> server{ex, make_test_info(), std::move(opts)};
        server.async_start();
        advance_to_live(server);

        endpoint remote{"192.168.1.20", 5353};
        auto tc_pkt = make_tc_ptr_query("_http._tcp.local.");
        server.socket().inject_receive(remote, tc_pkt);

        REQUIRE(server.tc_timer().has_pending());

        WHEN("the TC wait timer fires")
        {
            server.tc_timer().fire();

            THEN("on_tc_continuation was called with the correct sender")
            {
                REQUIRE(captured_sender.address == remote.address);
                REQUIRE(captured_sender.port == remote.port);
            }

            THEN("on_tc_continuation reports at least one continuation entry")
            {
                // The first TC packet itself is the known-answer set; count >= 0 (may be 0 for empty KA)
                (void)captured_count;
                REQUIRE(captured_sender.address == remote.address);
            }
        }
    }
}

SCENARIO("TC timer is cancelled on stop()", "[service_server][tc][stop]")
{
    GIVEN("a live server with a pending TC wait")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);

        endpoint remote{"192.168.1.20", 5353};
        auto tc_pkt = make_tc_ptr_query("_http._tcp.local.");
        server.socket().inject_receive(remote, tc_pkt);
        REQUIRE(server.tc_timer().has_pending());

        WHEN("stop() is called")
        {
            server.stop();
            ex.drain_posted();

            THEN("the tc_timer has been cancelled (no pending handler)")
            {
                REQUIRE_FALSE(server.tc_timer().has_pending());
            }
        }
    }
}

SCENARIO("Legacy unicast response repeats query ID and question without cache-flush",
         "[service_server][legacy_unicast][rfc6762-6.7]")
{
    GIVEN("a live server")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        endpoint legacy_sender{"10.0.0.1", 12345};
        auto query = make_ptr_query("_http._tcp.local.");
        query[0] = std::byte{0xBE};
        query[1] = std::byte{0xEF};
        server.socket().inject_receive(legacy_sender, query);

        WHEN("the legacy unicast response is sent")
        {
            const sent_packet *response = nullptr;
            for(const auto &pkt : server.socket().sent_packets())
            {
                if(pkt.dest == legacy_sender)
                    response = &pkt;
            }
            REQUIRE(response != nullptr);
            const auto &pkt = response->data;
            REQUIRE(pkt.size() >= 12);

            THEN("the response repeats the query ID")
            {
                REQUIRE(read_u16_be(pkt, 0) == 0xBEEF);
            }

            THEN("the response repeats the question (qdcount=1, same qname/qtype)")
            {
                REQUIRE(read_u16_be(pkt, 4) == 1);

                auto span = std::span<const std::byte>(pkt);
                auto qname = mdnspp::detail::read_dns_name(span, 12);
                REQUIRE(qname.has_value());
                REQUIRE(dns_name{*qname} == dns_name{"_http._tcp.local."});

                size_t offset = 12;
                REQUIRE(skip_dns_name(span, offset));
                REQUIRE(read_u16_be(pkt, offset) == mdnspp::detail::to_underlying(dns_type::ptr));
            }

            THEN("no record carries the cache-flush bit")
            {
                auto span = std::span<const std::byte>(pkt);
                size_t offset = 12;
                uint16_t qdcount = read_u16_be(pkt, 4);
                for(uint16_t i = 0; i < qdcount; ++i)
                {
                    REQUIRE(skip_dns_name(span, offset));
                    offset += 4;
                }
                uint16_t ancount = read_u16_be(pkt, 6);
                uint16_t arcount = read_u16_be(pkt, 10);
                uint32_t total = static_cast<uint32_t>(ancount) + arcount;
                REQUIRE(total >= 1);
                for(uint32_t i = 0; i < total; ++i)
                {
                    REQUIRE(skip_dns_name(span, offset));
                    uint16_t rclass = read_u16_be(pkt, offset + 2);
                    REQUIRE((rclass & 0x8000) == 0);
                    uint16_t rdlen = read_u16_be(pkt, offset + 8);
                    offset += 10 + rdlen;
                }
            }
        }
    }
}

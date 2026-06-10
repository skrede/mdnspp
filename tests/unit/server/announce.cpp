#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO("announcement burst sends announce_count announcements", "[service_server][announcing]")
{
    GIVEN("a service_server with announce_count=3")
    {
        mock_executor ex;

        service_options opts;
        opts.announce_count = 3;
        opts.announce_interval = std::chrono::milliseconds(500);
        opts.respond_to_meta_queries = false;

        basic_service_server<mock_policy> server{ex, make_test_info(), std::move(opts)};

        WHEN("probing completes and announcements are sent")
        {
            server.async_start();

            // Complete probing: 4 timer fires
            for(unsigned i = 0; i < 4; ++i)
                server.timer().fire();

            // After probing: first announcement is sent immediately.
            // Count announcement packets (flags=0x8400) after probing
            size_t probe_packets = 3; // 3 probes
            size_t after_probing = server.socket().sent_packets().size();
            // First announcement should be sent immediately after start_announcing
            REQUIRE(after_probing == probe_packets + 1); // 3 probes + 1 announcement

            // Fire timer for 2nd announcement
            server.timer().fire();
            REQUIRE(server.socket().sent_packets().size() == probe_packets + 2);

            // Fire timer for 3rd announcement
            server.timer().fire();

            THEN("3 announcements were sent total")
            {
                REQUIRE(server.socket().sent_packets().size() == probe_packets + 3);

                // Verify announcement packets have response flags
                for(size_t i = probe_packets; i < server.socket().sent_packets().size(); ++i)
                {
                    const auto &pkt = server.socket().sent_packets()[i].data;
                    REQUIRE(pkt.size() >= 4);
                    uint16_t flags = read_u16_be(pkt, 2);
                    REQUIRE(flags == 0x8400);
                    REQUIRE(server.socket().sent_packets()[i].dest == endpoint{"224.0.0.251", 5353});
                }
            }
        }
    }
}

SCENARIO("update_service_info sends announcement burst", "[service_server][update][burst]")
{
    GIVEN("a live service_server with announce_count=2")
    {
        mock_executor ex;

        service_options opts;
        opts.announce_count = 2;
        opts.respond_to_meta_queries = false;

        basic_service_server<mock_policy> server{ex, make_test_info(), std::move(opts)};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        WHEN("update_service_info is called")
        {
            auto new_info = make_test_info();
            new_info.port = 9090;
            server.update_service_info(std::move(new_info));
            ex.drain_posted();

            THEN("first announcement is sent immediately")
            {
                REQUIRE(server.socket().sent_packets().size() == 1);

                AND_WHEN("timer fires for second announcement")
                {
                    server.timer().fire();

                    THEN("second announcement is sent")
                    {
                        REQUIRE(server.socket().sent_packets().size() == 2);
                    }
                }
            }
        }
    }
}

// Helper: checks if a sent packet is a goodbye (all record TTLs are 0).
static bool is_goodbye_packet(const std::vector<std::byte> &pkt)
{
    if(pkt.size() < 12)
        return false;

    bool has_records = false;
    bool all_zero_ttl = true;
    walk_dns_frame(std::span<const std::byte>(pkt), endpoint{}, [&](mdns_record_variant rv)
    {
        has_records = true;
        std::visit([&](const auto &rec)
        {
            if(rec.ttl != 0)
                all_zero_ttl = false;
        }, rv);
    });
    return has_records && all_zero_ttl;
}

// Helper: count goodbye packets in a socket's sent_packets list.
static unsigned count_goodbye_packets(const std::vector<sent_packet> &packets)
{
    unsigned count = 0;
    for(const auto &sp : packets)
    {
        if(is_goodbye_packet(sp.data))
            ++count;
    }
    return count;
}

SCENARIO("Server sends goodbye packet on stop when live", "[goodbye]")
{
    GIVEN("a server that has been advanced to live state")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_service()};
        server.async_start();
        advance_to_live(server);

        WHEN("stop() is called and the posted teardown runs")
        {
            server.stop();
            ex.drain_posted();

            THEN("a goodbye packet with TTL=0 is sent")
            {
                auto goodbye_count = count_goodbye_packets(server.socket().sent_packets());
                REQUIRE(goodbye_count == 1);
            }

            THEN("the goodbye packet contains PTR, SRV, A records with TTL=0")
            {
                const auto &packets = server.socket().sent_packets();
                // Find the goodbye packet
                for(const auto &sp : packets)
                {
                    if(is_goodbye_packet(sp.data))
                    {
                        auto records = parse_response(sp.data);
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
                        break;
                    }
                }
            }
        }
    }
}

SCENARIO("Server does NOT send goodbye when stopped during probing", "[goodbye][probing]")
{
    GIVEN("a server that has been started but not advanced past probing")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_service()};
        server.async_start();
        // Fire only the initial delay timer, still in probing
        server.timer().fire();

        WHEN("stop() is called during probing")
        {
            server.stop();
            ex.drain_posted();

            THEN("no goodbye packet is sent")
            {
                auto goodbye_count = count_goodbye_packets(server.socket().sent_packets());
                REQUIRE(goodbye_count == 0);
            }
        }
    }
}

SCENARIO("Server skips goodbye when send_goodbye is false", "[goodbye][opt-out]")
{
    GIVEN("a server with send_goodbye=false that has been advanced to live")
    {
        mock_executor ex;
        service_options opts;
        opts.send_goodbye = false;
        basic_service_server<mock_policy> server{ex, make_test_service(), std::move(opts)};
        server.async_start();
        advance_to_live(server);

        WHEN("stop() is called")
        {
            server.stop();
            ex.drain_posted();

            THEN("no goodbye packet is sent")
            {
                auto goodbye_count = count_goodbye_packets(server.socket().sent_packets());
                REQUIRE(goodbye_count == 0);
            }
        }
    }
}

SCENARIO("Goodbye sent at most once on double stop", "[goodbye][idempotent]")
{
    GIVEN("a server that has been advanced to live state")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_service()};
        server.async_start();
        advance_to_live(server);

        WHEN("stop() is called twice")
        {
            server.stop();
            server.stop();
            ex.drain_posted();

            THEN("exactly one goodbye packet is sent")
            {
                auto goodbye_count = count_goodbye_packets(server.socket().sent_packets());
                REQUIRE(goodbye_count == 1);
            }
        }
    }
}

SCENARIO("Server sends goodbye when stopped during announcing", "[goodbye][announcing]")
{
    GIVEN("a server that has completed probing but is still announcing")
    {
        mock_executor ex;
        service_options opts;
        opts.announce_count = 3; // need 3 announcements
        basic_service_server<mock_policy> server{ex, make_test_service(), std::move(opts)};
        server.async_start();

        // Complete probing: 4 timer fires
        for(unsigned i = 0; i < 4; ++i)
            server.timer().fire();

        // Fire only 1 additional announcement timer (out of announce_count-1=2 needed)
        // State should be announcing
        server.timer().fire();

        WHEN("stop() is called during announcing")
        {
            server.stop();
            ex.drain_posted();

            THEN("a goodbye packet is sent")
            {
                auto goodbye_count = count_goodbye_packets(server.socket().sent_packets());
                REQUIRE(goodbye_count == 1);
            }
        }
    }
}

SCENARIO("update_service_info posts work to executor", "[service_server][update]")
{
    GIVEN("a live service_server")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);

        WHEN("update_service_info() is called with new service_info")
        {
            auto new_info = make_test_info();
            new_info.port = 9090;
            new_info.txt_records = {service_txt{"version", "2.0"}};

            server.update_service_info(std::move(new_info));

            THEN("a lambda was posted to the executor")
            {
                REQUIRE(ex.m_posted.size() == 1);

                AND_WHEN("the posted work is drained")
                {
                    server.socket().clear_sent();
                    ex.drain_posted();

                    THEN("the socket has a sent packet (first announcement of burst)")
                    {
                        REQUIRE_FALSE(server.socket().sent_packets().empty());
                    }
                }
            }
        }
    }
}

SCENARIO("Server invokes on_error with invalid_ipv4_address when address encoding fails",
         "[service_server][on_error][address_encoding]")
{
    GIVEN("a service_server with an invalid IPv4 address and an on_error handler")
    {
        mock_executor ex;

        std::vector<std::error_code> error_codes;
        std::vector<std::string> error_msgs;

        service_options opts;
        opts.respond_to_meta_queries = false;
        opts.on_error = [&](std::error_code ec, std::string_view msg)
        {
            error_codes.push_back(ec);
            error_msgs.push_back(std::string(msg));
        };

        service_info info = make_test_info();
        info.address_ipv4 = "999.1.2.3";  // intentionally malformed

        basic_service_server<mock_policy> server{ex, std::move(info), std::move(opts)};

        server.async_start();
        advance_to_live(server);

        THEN("on_error was invoked at least once with invalid_ipv4_address")
        {
            REQUIRE_FALSE(error_codes.empty());
            bool found = false;
            for(const auto &ec : error_codes)
            {
                if(ec == make_error_code(mdnspp::mdns_error::invalid_ipv4_address))
                {
                    found = true;
                    break;
                }
            }
            REQUIRE(found);
        }
    }
}

SCENARIO("update_service_info sends unsolicited announcement to multicast", "[service_server][update][announcement]")
{
    GIVEN("a live service_server")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);

        WHEN("update_service_info() is called and posted work is drained")
        {
            auto new_info = make_test_info();
            new_info.port = 9090;
            server.update_service_info(std::move(new_info));
            server.socket().clear_sent();
            ex.drain_posted();

            THEN("a packet was sent to 224.0.0.251:5353")
            {
                REQUIRE_FALSE(server.socket().sent_packets().empty());
                REQUIRE(server.socket().sent_packets().back().dest == endpoint{"224.0.0.251", 5353});

                AND_THEN("the packet is non-empty DNS response data")
                {
                    REQUIRE_FALSE(server.socket().sent_packets().back().data.empty());
                }
            }
        }
    }
}

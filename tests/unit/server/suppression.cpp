#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

SCENARIO("NSEC in Additional for unmatched type", "[nsec]")
{
    GIVEN("a live service server with IPv4 only (no IPv6)")
    {
        mock_executor ex;
        auto info = make_test_service();
        info.address_ipv6 = std::nullopt; // no IPv6
        basic_service_server<mock_policy> server{ex, std::move(info)};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        WHEN("an AAAA query for our hostname is injected")
        {
            auto query = build_dns_query("myhost.local.", dns_type::aaaa, response_mode::multicast);
            endpoint sender{"192.168.1.50", 5353};
            server.socket().inject_receive(sender, std::move(query));
            server.timer().fire();

            THEN("the response contains an NSEC record in Additional")
            {
                REQUIRE_FALSE(server.socket().sent_packets().empty());
                const auto &pkt = server.socket().sent_packets().back().data;
                REQUIRE(pkt.size() >= 12);

                // Check arcount > 0 (NSEC is in Additional)
                uint16_t arcount = read_u16_be(pkt, 10);
                REQUIRE(arcount >= 1);

                // Parse and verify NSEC record exists
                // Walk the raw packet bytes to find NSEC type (47)
                bool found_nsec = false;
                auto cdata = std::span<const std::byte>(pkt.data(), pkt.size());
                size_t offset = 12;

                // Skip questions
                uint16_t qdcount = read_u16_be(pkt.data() + 4);
                for(uint16_t i = 0; i < qdcount; ++i)
                {
                    skip_dns_name(cdata, offset);
                    offset += 4;
                }

                // Walk all RRs
                uint16_t ancount = read_u16_be(pkt.data() + 6);
                uint16_t nscount = read_u16_be(pkt.data() + 8);
                uint32_t rr_total = static_cast<uint32_t>(ancount) + nscount + arcount;
                for(uint32_t rr = 0; rr < rr_total; ++rr)
                {
                    if(!skip_dns_name(cdata, offset) || offset + 10 > pkt.size())
                        break;
                    uint16_t rtype = read_u16_be(pkt.data() + offset);
                    offset += 2;
                    offset += 2; // rclass
                    offset += 4; // ttl
                    uint16_t rdlen = read_u16_be(pkt.data() + offset);
                    offset += 2;
                    if(rtype == mdnspp::detail::to_underlying(dns_type::nsec))
                        found_nsec = true;
                    offset += rdlen;
                }
                REQUIRE(found_nsec);
            }
        }
    }
}

SCENARIO("No NSEC in announcements", "[nsec][announce]")
{
    GIVEN("a service server that is advancing through announcing")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_service()};
        server.async_start();
        advance_to_live(server);

        THEN("none of the announcement packets contain NSEC records")
        {
            for(const auto &sp : server.socket().sent_packets())
            {
                if(sp.data.size() < 12) continue;

                // Check for NSEC (type 47) in each packet
                auto cdata = std::span<const std::byte>(sp.data.data(), sp.data.size());
                size_t offset = 12;

                uint16_t qdcount = read_u16_be(sp.data.data() + 4);
                for(uint16_t i = 0; i < qdcount; ++i)
                {
                    if(!skip_dns_name(cdata, offset)) break;
                    offset += 4;
                }

                uint16_t ancount = read_u16_be(sp.data.data() + 6);
                uint16_t nscount = read_u16_be(sp.data.data() + 8);
                uint16_t arcount = read_u16_be(sp.data.data() + 10);
                uint32_t rr_total = static_cast<uint32_t>(ancount) + nscount + arcount;

                for(uint32_t rr = 0; rr < rr_total; ++rr)
                {
                    if(!skip_dns_name(cdata, offset) || offset + 10 > sp.data.size())
                        break;
                    uint16_t rtype = read_u16_be(sp.data.data() + offset);
                    REQUIRE(rtype != mdnspp::detail::to_underlying(dns_type::nsec));
                    offset += 2;
                    offset += 2; // rclass
                    offset += 4; // ttl
                    uint16_t rdlen = read_u16_be(sp.data.data() + offset);
                    offset += 2;
                    offset += rdlen;
                }
            }
        }
    }
}

// Helper: build a DNS query with a known-answer section.
// Constructs a query for qname/qtype followed by one answer RR.
static std::vector<std::byte> make_query_with_known_answer(
    std::string_view qname, dns_type qtype,
    std::string_view answer_name, dns_type answer_rtype, uint32_t answer_ttl,
    const std::vector<std::byte> &answer_rdata)
{
    std::vector<std::byte> packet;

    // Header: id=0, flags=0, qdcount=1, ancount=1, nscount=0, arcount=0
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0001); // qdcount
    push_u16_be(packet, 0x0001); // ancount
    push_u16_be(packet, 0x0000);
    push_u16_be(packet, 0x0000);

    // Question section
    auto encoded_qname = encode_dns_name(qname).value();
    packet.insert(packet.end(), encoded_qname.begin(), encoded_qname.end());
    push_u16_be(packet, mdnspp::detail::to_underlying(qtype));
    push_u16_be(packet, 0x0001); // qclass=IN (multicast)

    // Answer section
    auto encoded_answer = encode_dns_name(answer_name).value();
    append_dns_rr(packet, encoded_answer, answer_rtype, answer_ttl, answer_rdata, false);

    return packet;
}

SCENARIO("known-answer suppression skips records with TTL >= 50%", "[known-answer-suppression]")
{
    GIVEN("a live service server")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        WHEN("a PTR query with known answer TTL=3000 (>2250) is injected")
        {
            // Build PTR rdata pointing to service_name
            auto ptr_rdata = encode_dns_name("MyService._http._tcp.local.").value();

            auto query = make_query_with_known_answer(
                "_http._tcp.local.", dns_type::ptr,
                "_http._tcp.local.", dns_type::ptr, 3000,
                ptr_rdata);

            endpoint sender{"192.168.1.50", 5353};
            server.socket().inject_receive(sender, std::move(query));
            server.timer().fire();

            THEN("the response does not contain a PTR record (suppressed)")
            {
                // Either no response at all, or response without PTR
                bool has_ptr = false;
                for(const auto &sp : server.socket().sent_packets())
                {
                    auto records = parse_response(sp.data);
                    for(const auto &rv : records)
                    {
                        if(std::holds_alternative<record_ptr>(rv))
                            has_ptr = true;
                    }
                }
                REQUIRE_FALSE(has_ptr);
            }
        }
    }
}

SCENARIO("suppress_known_answers=false sends full response", "[known-answer-suppression][disable]")
{
    GIVEN("a live service server with suppress_known_answers=false")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info(),
            service_options{.suppress_known_answers = false}};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        WHEN("a PTR query with known answer TTL=3000 is injected")
        {
            auto ptr_rdata = encode_dns_name("MyService._http._tcp.local.").value();

            auto query = make_query_with_known_answer(
                "_http._tcp.local.", dns_type::ptr,
                "_http._tcp.local.", dns_type::ptr, 3000,
                ptr_rdata);

            endpoint sender{"192.168.1.50", 5353};
            server.socket().inject_receive(sender, std::move(query));
            server.timer().fire();

            THEN("the response DOES contain a PTR record (suppression disabled)")
            {
                REQUIRE_FALSE(server.socket().sent_packets().empty());
                const auto &pkt = server.socket().sent_packets().back();
                auto records = parse_response(pkt.data);

                bool has_ptr = false;
                for(const auto &rv : records)
                {
                    if(std::holds_alternative<record_ptr>(rv))
                        has_ptr = true;
                }
                REQUIRE(has_ptr);
            }
        }
    }
}

// Builds a minimal mDNS response packet (QR=1) with one PTR answer for the given service.
// Used to simulate another responder multicasting an answer during the 20-120ms delay window.
static std::vector<std::byte> make_ptr_response(const service_info &info)
{
    return build_dns_response(info, dns_type::ptr, service_options{});
}

SCENARIO("Multicast response from another host suppresses our answer during delay window",
         "[service_server][duplicate-suppression][rfc6762]")
{
    GIVEN("a live service server with a pending multicast response")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);

        // Inject a normal PTR query to arm the response timer (20-120ms delay)
        auto query_pkt = make_ptr_query("_http._tcp.local.");
        server.socket().inject_receive(endpoint{}, query_pkt);

        REQUIRE(server.timer().has_pending());
        auto sent_before = server.socket().sent_packets().size();

        WHEN("another host's PTR response arrives before the delay timer fires")
        {
            // Simulate another responder sending a matching response during the window
            auto response_pkt = make_ptr_response(make_test_info());
            // Ensure the response packet has QR=1 (it's a response from build_dns_response)
            server.socket().inject_receive(endpoint{"192.168.1.99", 5353}, response_pkt);

            THEN("the response from the other host is observed (m_dup_suppression populated)")
            {
                // The observation happens inline; fire the delay timer and check suppression.
                // If suppression works, the server may send fewer records or nothing at all.
                server.timer().fire();

                // The exact suppression effect depends on record identity match.
                // The key invariant: the server did not crash and processed gracefully.
                // The sent_packets count should not have grown by a PTR-only packet
                // because the PTR was already answered by the other host.
                // Since all records match (same service_info), all are suppressed and no packet is sent.
                auto sent_after = server.socket().sent_packets().size();
                REQUIRE(sent_after == sent_before); // suppressed -- no duplicate sent
            }
        }

        WHEN("no other response arrives before the delay timer fires")
        {
            server.timer().fire();

            THEN("the server sends its own response normally")
            {
                auto sent_after = server.socket().sent_packets().size();
                REQUIRE(sent_after > sent_before);
            }
        }
    }
}

SCENARIO("known answer with stale rdata does NOT suppress the answer", "[known-answer-suppression][rdata]")
{
    GIVEN("a live service server")
    {
        mock_executor ex;
        basic_service_server<mock_policy> server{ex, make_test_info()};
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();

        WHEN("an SRV query carries a known answer with a stale port")
        {
            // RFC 6762 §7.1: suppression requires matching rdata. A querier
            // holding a stale SRV (old port) must still receive our answer.
            std::vector<std::byte> stale_rdata;
            push_u16_be(stale_rdata, 0);    // priority
            push_u16_be(stale_rdata, 0);    // weight
            push_u16_be(stale_rdata, 9999); // stale port (ours is 8080)
            auto target = encode_dns_name("myhost.local.").value();
            stale_rdata.insert(stale_rdata.end(), target.begin(), target.end());

            auto query = make_query_with_known_answer(
                "MyService._http._tcp.local.", dns_type::srv,
                "MyService._http._tcp.local.", dns_type::srv, 4500,
                stale_rdata);

            endpoint sender{"192.168.1.50", 5353};
            server.socket().inject_receive(sender, std::move(query));
            server.timer().fire(); // in case the response was delayed

            THEN("the response contains our SRV record with the correct port")
            {
                bool has_correct_srv = false;
                for(const auto &sp : server.socket().sent_packets())
                {
                    auto records = parse_response(sp.data);
                    for(const auto &rv : records)
                    {
                        if(const auto *srv = std::get_if<record_srv>(&rv))
                        {
                            if(srv->port == 8080)
                                has_correct_srv = true;
                        }
                    }
                }
                REQUIRE(has_correct_srv);
            }
        }

        WHEN("an SRV query carries a known answer with matching rdata")
        {
            std::vector<std::byte> matching_rdata;
            push_u16_be(matching_rdata, 0);
            push_u16_be(matching_rdata, 0);
            push_u16_be(matching_rdata, 8080);
            auto target = encode_dns_name("myhost.local.").value();
            matching_rdata.insert(matching_rdata.end(), target.begin(), target.end());

            auto query = make_query_with_known_answer(
                "MyService._http._tcp.local.", dns_type::srv,
                "MyService._http._tcp.local.", dns_type::srv, 4500,
                matching_rdata);

            endpoint sender{"192.168.1.50", 5353};
            server.socket().inject_receive(sender, std::move(query));
            server.timer().fire();

            THEN("no SRV answer is sent (suppressed)")
            {
                bool has_srv = false;
                for(const auto &sp : server.socket().sent_packets())
                {
                    auto records = parse_response(sp.data);
                    for(const auto &rv : records)
                    {
                        if(std::holds_alternative<record_srv>(rv))
                            has_srv = true;
                    }
                }
                REQUIRE_FALSE(has_srv);
            }
        }
    }
}

#include "fixture.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstddef>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <string_view>

namespace {

std::vector<std::byte> make_query_with_known_answer(
    std::string_view qname, dns_type qtype,
    std::string_view answer_name, dns_type answer_rtype, uint32_t answer_ttl,
    const std::vector<std::byte> &answer_rdata)
{
    std::vector<std::byte> packet;
    push_u16_be(packet, 0x0000); // id
    push_u16_be(packet, 0x0000); // flags
    push_u16_be(packet, 0x0001); // qdcount
    push_u16_be(packet, 0x0001); // ancount
    push_u16_be(packet, 0x0000); // nscount
    push_u16_be(packet, 0x0000); // arcount
    auto encoded_qname = encode_dns_name(qname).value();
    packet.insert(packet.end(), encoded_qname.begin(), encoded_qname.end());
    push_u16_be(packet, mdnspp::detail::to_underlying(qtype));
    push_u16_be(packet, 0x0001); // qclass=IN (multicast)
    auto encoded_answer = encode_dns_name(answer_name).value();
    append_dns_rr(packet, encoded_answer, answer_rtype, answer_ttl, answer_rdata, false);
    return packet;
}

std::vector<std::byte> ptr_known_answer_query(uint32_t ttl)
{
    auto ptr_rdata = encode_dns_name("MyService._http._tcp.local.").value();
    return make_query_with_known_answer("_http._tcp.local.", dns_type::ptr, "_http._tcp.local.", dns_type::ptr, ttl,
                                        ptr_rdata);
}

std::vector<std::byte> srv_known_answer_query(uint16_t port)
{
    std::vector<std::byte> rdata;
    push_u16_be(rdata, 0); // priority
    push_u16_be(rdata, 0); // weight
    push_u16_be(rdata, port);
    auto target = encode_dns_name("myhost.local.").value();
    rdata.insert(rdata.end(), target.begin(), target.end());
    return make_query_with_known_answer("MyService._http._tcp.local.", dns_type::srv, "MyService._http._tcp.local.",
                                        dns_type::srv, 4500, rdata);
}

void respond_to(server_fixture &f, std::vector<std::byte> query)
{
    f.inject(endpoint{"192.168.1.50", 5353}, std::move(query));
    f.server.delay_timer().fire();
}

template <typename Record>
bool any_sent_contains(const std::vector<sent_packet> &sent)
{
    return std::ranges::any_of(sent, [](const sent_packet &sp) { return contains_record<Record>(sp.data); });
}

bool any_srv_on_port(const std::vector<sent_packet> &sent, uint16_t port)
{
    return std::ranges::any_of(sent, [port](const sent_packet &sp)
    {
        return contains_record_where<record_srv>(sp.data, [port](const record_srv &srv) { return srv.port == port; });
    });
}

std::size_t arm_response_timer(server_fixture &f)
{
    f.inject(endpoint{}, make_ptr_query("_http._tcp.local."));
    REQUIRE(f.server.delay_timer().has_pending());
    return f.sent().size();
}

void no_other_response_section(server_fixture &f, std::size_t sent_before)
{
    WHEN("no other response arrives before the delay timer fires")
    {
        f.server.delay_timer().fire();

        THEN("the server sends its own response normally")
        {
            REQUIRE(f.sent().size() > sent_before);
        }
    }
}

void matching_rdata_section(server_fixture &f)
{
    WHEN("an SRV query carries a known answer with matching rdata")
    {
        respond_to(f, srv_known_answer_query(8080));

        THEN("no SRV answer is sent (suppressed)")
        {
            REQUIRE_FALSE(any_sent_contains<record_srv>(f.sent()));
        }
    }
}

}

SCENARIO("known-answer suppression skips records with TTL >= 50%", "[known-answer-suppression]")
{
    GIVEN("a live service server")
    {
        server_fixture f;
        f.go_live();
        f.clear_sent();

        WHEN("a PTR query with known answer TTL=3000 (>2250) is injected")
        {
            respond_to(f, ptr_known_answer_query(3000));

            THEN("the response does not contain a PTR record (suppressed)")
            {
                REQUIRE_FALSE(any_sent_contains<record_ptr>(f.sent()));
            }
        }
    }
}

SCENARIO("suppress_known_answers=false sends full response", "[known-answer-suppression][disable]")
{
    GIVEN("a live service server with suppress_known_answers=false")
    {
        server_fixture f{make_test_info(), service_options{.suppress_known_answers = false}};
        f.go_live();
        f.clear_sent();

        WHEN("a PTR query with known answer TTL=3000 is injected")
        {
            respond_to(f, ptr_known_answer_query(3000));

            THEN("the response DOES contain a PTR record (suppression disabled)")
            {
                REQUIRE_FALSE(f.sent().empty());
                REQUIRE(contains_record<record_ptr>(f.sent().back().data));
            }
        }
    }
}

SCENARIO("Multicast response from another host suppresses our answer during delay window",
         "[service_server][duplicate-suppression][rfc6762]")
{
    GIVEN("a live service server with a pending multicast response")
    {
        server_fixture f;
        f.go_live();
        std::size_t sent_before = arm_response_timer(f);

        WHEN("another host's PTR response arrives before the delay timer fires")
        {
            auto response = build_dns_response(make_test_info(), dns_type::ptr, service_options{});
            f.inject(endpoint{"192.168.1.99", 5353}, std::move(response));

            THEN("the response from the other host is observed (m_dup_suppression populated)")
            {
                // Every record matches the other host's answer, so all are suppressed and nothing is sent.
                f.server.delay_timer().fire();
                REQUIRE(f.sent().size() == sent_before);
            }
        }

        no_other_response_section(f, sent_before);
    }
}

SCENARIO("known answer with stale rdata does NOT suppress the answer", "[known-answer-suppression][rdata]")
{
    GIVEN("a live service server")
    {
        server_fixture f;
        f.go_live();
        f.clear_sent();

        WHEN("an SRV query carries a known answer with a stale port")
        {
            // RFC 6762 §7.1: suppression requires matching rdata, so a querier holding a stale SRV still gets ours.
            respond_to(f, srv_known_answer_query(9999)); // ours is 8080

            THEN("the response contains our SRV record with the correct port")
            {
                REQUIRE(any_srv_on_port(f.sent(), 8080));
            }
        }

        matching_rdata_section(f);
    }
}

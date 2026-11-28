#include "helpers.h"

using mdnspp::detail::build_dns_query_tc;

static bool has_tc_bit(const std::vector<std::byte> &pkt)
{
    if(pkt.size() < 4) return false;
    return (std::to_integer<uint8_t>(pkt[2]) & 0x02u) != 0;
}

static uint16_t packet_ancount(const std::vector<std::byte> &pkt)
{
    if(pkt.size() < 8) return 0;
    return ::read_u16_be(pkt, 6);
}

static std::vector<mdnspp::mdns_record_variant> make_large_ptr_known_answers(std::size_t count)
{
    std::vector<mdnspp::mdns_record_variant> records;
    records.reserve(count);
    for(std::size_t i = 0; i < count; ++i)
        records.push_back(make_ptr_record("_http._tcp.local.", "VeryLongServiceInstanceName" + std::to_string(i) +
                                                               "ExtraLongSuffixForSizePadding._http._tcp.local."));
    return records;
}

static void check_single_packet_contents(const std::vector<std::vector<std::byte>> &packets)
{
    THEN("the single packet does NOT have the TC bit set")
    {
        REQUIRE(packets.size() == 1);
        REQUIRE_FALSE(has_tc_bit(packets[0]));
    }

    THEN("the single packet contains the known answer (ancount=1)")
    {
        REQUIRE(packets.size() == 1);
        REQUIRE(packet_ancount(packets[0]) == 1);
    }
}

static void check_first_and_last_tc(const std::vector<std::vector<std::byte>> &packets)
{
    THEN("the first packet has TC bit set")
    {
        REQUIRE(has_tc_bit(packets.front()));
    }

    THEN("the last packet does NOT have TC bit set")
    {
        REQUIRE_FALSE(has_tc_bit(packets.back()));
    }
}

static void check_split_packets(const std::vector<std::vector<std::byte>> &packets)
{
    THEN("every packet is <= 1472 bytes")
    {
        for(const auto &pkt : packets)
            REQUIRE(pkt.size() <= 1472);
    }

    THEN("every intermediate packet has TC bit set")
    {
        for(std::size_t i = 0; i + 1 < packets.size(); ++i)
            REQUIRE(has_tc_bit(packets[i]));
    }

    THEN("only the first packet carries questions; continuations have qdcount=0 (RFC 6762 §7.2)")
    {
        REQUIRE(::read_u16_be(packets.front(), 4) == 1);
        for(std::size_t i = 1; i < packets.size(); ++i)
            REQUIRE(::read_u16_be(packets[i], 4) == 0);
    }
}

// RFC 6762 section 7.1 known-answer TC splitting.
SCENARIO("build_dns_query_tc returns single packet when answers fit in max_payload",
         "[dns_wire][tc][known_answer]")
{
    GIVEN("a few small known answers well under 1472 bytes")
    {
        std::vector<mdnspp::mdns_record_variant> known = {
            make_ptr_record("_http._tcp.local.", "MyService._http._tcp.local.")};
        WHEN("build_dns_query_tc is called with default max_payload=1472")
        {
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr, known);
            THEN("exactly one packet is returned")
            {
                REQUIRE(packets.size() == 1);
            }

            check_single_packet_contents(packets);
        }
    }
}

SCENARIO("build_dns_query_tc returns single packet for empty known answers",
         "[dns_wire][tc][known_answer]")
{
    GIVEN("no known answers")
    {
        std::span<const mdnspp::mdns_record_variant> empty;
        WHEN("build_dns_query_tc is called")
        {
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr, empty);
            THEN("exactly one packet is returned")
            {
                REQUIRE(packets.size() == 1);
            }

            THEN("the packet does not have TC bit set")
            {
                REQUIRE_FALSE(has_tc_bit(packets[0]));
            }

            THEN("ancount is 0")
            {
                REQUIRE(packet_ancount(packets[0]) == 0);
            }
        }
    }
}

SCENARIO("build_dns_query_tc splits large known-answer list across packets",
         "[dns_wire][tc][known_answer][split]")
{
    GIVEN("enough PTR records to exceed 1472 bytes when combined")
    {
        // About 85 bytes per PTR record, so more than 1472 / 85 (about 18) records split.
        auto known = make_large_ptr_known_answers(25);
        WHEN("build_dns_query_tc is called with default max_payload=1472")
        {
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr, known);
            THEN("more than one packet is returned")
            {
                REQUIRE(packets.size() > 1);
            }

            check_first_and_last_tc(packets);
            check_split_packets(packets);
        }
    }
}

SCENARIO("build_dns_query_tc respects custom max_payload causing more aggressive splitting",
         "[dns_wire][tc][known_answer][split]")
{
    GIVEN("several PTR known answers and a small max_payload of 200 bytes")
    {
        auto known = make_large_ptr_known_answers(5);
        WHEN("build_dns_query_tc is called with max_payload=200")
        {
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr, known, 200);
            THEN("more than one packet is returned (aggressive splitting)")
            {
                REQUIRE(packets.size() > 1);
            }

            THEN("every packet is <= 200 bytes")
            {
                for(const auto &pkt : packets)
                    REQUIRE(pkt.size() <= 200);
            }

            check_first_and_last_tc(packets);
        }
    }
}

SCENARIO("build_dns_query_tc ancount matches answers per packet",
         "[dns_wire][tc][known_answer][ancount]")
{
    GIVEN("enough PTR records to fill multiple packets at max_payload=300")
    {
        auto known = make_large_ptr_known_answers(8);
        WHEN("build_dns_query_tc is called with max_payload=300")
        {
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr, known, 300);
            THEN("each packet's ancount matches the number of answers it actually contains")
            {
                uint32_t total_claimed = 0;
                for(const auto &pkt : packets)
                {
                    uint16_t an = packet_ancount(pkt);
                    REQUIRE(an > 0);
                    total_claimed += an;
                }
                REQUIRE(total_claimed == static_cast<uint32_t>(known.size()));
            }
        }
    }
}

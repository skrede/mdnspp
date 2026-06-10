// Unit tests for build_dns_query known-answer, build_dns_query_tc
// (RFC 6762 §7.1 known-answer TC splitting), and parse_service_type.

#include "helpers.h"

using mdnspp::detail::build_dns_query;
using mdnspp::detail::build_dns_query_tc;
using mdnspp::detail::walk_dns_frame;
using mdnspp::detail::append_known_answer;
using mdnspp::detail::push_u16_be;
using mdnspp::parse_service_type;

static std::vector<mdnspp::mdns_record_variant> parse_wire(const std::vector<std::byte> &pkt)
{
    std::vector<mdnspp::mdns_record_variant> records;
    walk_dns_frame(std::span<const std::byte>(pkt), mdnspp::endpoint{}, [&](mdnspp::mdns_record_variant rv)
    {
        records.push_back(std::move(rv));
    });
    return records;
}

// Helper: check that a packet has TC bit set (byte 2, bit 1)
static bool has_tc_bit(const std::vector<std::byte> &pkt)
{
    if(pkt.size() < 4) return false;
    return (std::to_integer<uint8_t>(pkt[2]) & 0x02u) != 0;
}

// Helper: extract ancount from a packet header
static uint16_t packet_ancount(const std::vector<std::byte> &pkt)
{
    if(pkt.size() < 8) return 0;
    return ::read_u16_be(pkt, 6);
}

// Helper: build a vector of PTR records with a given long name prefix to create large known-answer lists
static std::vector<mdnspp::mdns_record_variant> make_large_ptr_known_answers(
    std::size_t count, std::string_view base_name = "_http._tcp.local.")
{
    std::vector<mdnspp::mdns_record_variant> records;
    records.reserve(count);
    for(std::size_t i = 0; i < count; ++i)
    {
        mdnspp::record_ptr ptr;
        ptr.name = std::string(base_name);
        ptr.ttl = 4500;
        // Use a long enough name to ensure each record contributes ~100+ bytes
        ptr.ptr_name = "VeryLongServiceInstanceName" + std::to_string(i) +
                       "ExtraLongSuffixForSizePadding._http._tcp.local.";
        records.push_back(ptr);
    }
    return records;
}

SCENARIO("build_dns_query with known answers includes Answer section", "[dns_wire][known_answer]")
{
    GIVEN("a PTR record as a known answer")
    {
        mdnspp::record_ptr ptr;
        ptr.name = "_http._tcp.local";
        ptr.ttl = 4500;
        ptr.ptr_name = "MyService._http._tcp.local";

        std::vector<mdnspp::mdns_record_variant> known = {ptr};

        WHEN("build_dns_query is called with the known answer")
        {
            auto pkt = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr,
                                       std::span<const mdnspp::mdns_record_variant>(known));

            THEN("the header ancount is 1")
            {
                REQUIRE(pkt.size() >= 12);
                uint16_t ancount = mdnspp::detail::read_u16_be(pkt.data() + 6);
                REQUIRE(ancount == 1);
            }

            THEN("the packet is longer than a basic query")
            {
                auto basic = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr);
                REQUIRE(pkt.size() > basic.size());
            }

            THEN("walk_dns_frame can parse the known-answer PTR record")
            {
                // To parse as a response frame, we need QR=1 in flags.
                // Modify flags to make it parseable by walk_dns_frame.
                auto parseable = pkt;
                // Set qdcount=0 so walk_dns_frame skips question section
                // Actually walk_dns_frame skips questions by count, so let's
                // just verify the answer section by manually checking.
                auto records = parse_wire(pkt);
                // walk_dns_frame skips questions by qdcount, then reads ancount RRs.
                // Our packet has qdcount=1 and ancount=1, so it will skip the question
                // and parse the answer section.
                bool found_ptr = false;
                for(const auto &rv : records)
                {
                    if(auto *p = std::get_if<mdnspp::record_ptr>(&rv))
                    {
                        found_ptr = true;
                        REQUIRE(p->ptr_name == "MyService._http._tcp.local.");
                    }
                }
                REQUIRE(found_ptr);
            }
        }
    }
}

SCENARIO("append_known_answer omits record_a with invalid address string",
         "[dns_wire][known_answer][error_handling]")
{
    GIVEN("a record_a with an invalid address string '999.1.2.3'")
    {
        mdnspp::record_a bad_a;
        bad_a.name = "myhost.local.";
        bad_a.ttl = 120;
        bad_a.address_string = "999.1.2.3";

        mdnspp::mdns_record_variant bad_rec = bad_a;

        WHEN("append_known_answer is called with this record")
        {
            std::vector<std::byte> buf;
            std::size_t size_before = buf.size();
            append_known_answer(buf, bad_rec);

            THEN("the buffer size is unchanged (record was not appended)")
            {
                REQUIRE(buf.size() == size_before);
            }
        }
    }
}

SCENARIO("build_dns_query with empty known answers matches basic overload", "[dns_wire][known_answer]")
{
    GIVEN("an empty known-answers span")
    {
        std::span<const mdnspp::mdns_record_variant> empty;

        WHEN("both overloads are called for the same query")
        {
            auto basic = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr);
            auto with_empty = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr, empty);

            THEN("the output is byte-for-byte identical")
            {
                REQUIRE(basic == with_empty);
            }
        }
    }
}

// ---------------------------------------------------------------------------
// parse_service_type tests
// ---------------------------------------------------------------------------

SCENARIO("parse_service_type splits PTR name into components", "[dns_wire][parse_service_type]")
{
    GIVEN("the service type _http._tcp.local")
    {
        auto info = parse_service_type("_http._tcp.local");

        THEN("type_name is _http, protocol is _tcp, domain is local")
        {
            REQUIRE(info.type_name == "_http");
            REQUIRE(info.protocol == "_tcp");
            REQUIRE(info.domain == "local");
            REQUIRE(info.service_type == "_http._tcp.local");
        }
    }

    GIVEN("the service type _ipp._tcp.local. with trailing dot")
    {
        auto info = parse_service_type("_ipp._tcp.local.");

        THEN("trailing dot is stripped and components are correct")
        {
            REQUIRE(info.type_name == "_ipp");
            REQUIRE(info.protocol == "_tcp");
            REQUIRE(info.domain == "local");
            REQUIRE(info.service_type == "_ipp._tcp.local");
        }
    }
}

// ---------------------------------------------------------------------------
// build_dns_query_tc tests -- RFC 6762 §7.1 known-answer TC splitting
// ---------------------------------------------------------------------------

SCENARIO("build_dns_query_tc returns single packet when answers fit in max_payload",
         "[dns_wire][tc][known_answer]")
{
    GIVEN("a few small known answers well under 1472 bytes")
    {
        mdnspp::record_ptr ptr;
        ptr.name = "_http._tcp.local.";
        ptr.ttl = 4500;
        ptr.ptr_name = "MyService._http._tcp.local.";

        std::vector<mdnspp::mdns_record_variant> known = {ptr};

        WHEN("build_dns_query_tc is called with default max_payload=1472")
        {
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr,
                                              std::span<const mdnspp::mdns_record_variant>(known));

            THEN("exactly one packet is returned")
            {
                REQUIRE(packets.size() == 1);
            }

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
        // Each PTR record is roughly: name(~20 bytes) + type(2) + class(2) + ttl(4) +
        //   rdlen(2) + ptr_name(~55 bytes) = ~85 bytes
        // Need > 1472/85 ~ 18 records to split
        auto known = make_large_ptr_known_answers(25);

        WHEN("build_dns_query_tc is called with default max_payload=1472")
        {
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr,
                                              std::span<const mdnspp::mdns_record_variant>(known));

            THEN("more than one packet is returned")
            {
                REQUIRE(packets.size() > 1);
            }

            THEN("the first packet has TC bit set")
            {
                REQUIRE(has_tc_bit(packets.front()));
            }

            THEN("the last packet does NOT have TC bit set")
            {
                REQUIRE_FALSE(has_tc_bit(packets.back()));
            }

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
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr,
                                              std::span<const mdnspp::mdns_record_variant>(known),
                                              200);

            THEN("more than one packet is returned (aggressive splitting)")
            {
                REQUIRE(packets.size() > 1);
            }

            THEN("every packet is <= 200 bytes")
            {
                for(const auto &pkt : packets)
                    REQUIRE(pkt.size() <= 200);
            }

            THEN("the first packet has TC bit set")
            {
                REQUIRE(has_tc_bit(packets.front()));
            }

            THEN("the last packet does NOT have TC bit set")
            {
                REQUIRE_FALSE(has_tc_bit(packets.back()));
            }
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
            auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr,
                                              std::span<const mdnspp::mdns_record_variant>(known),
                                              300);

            THEN("each packet's ancount matches the number of answers it actually contains")
            {
                // Count total answers claimed vs expected
                uint32_t total_claimed = 0;
                for(const auto &pkt : packets)
                {
                    uint16_t an = packet_ancount(pkt);
                    REQUIRE(an > 0); // each packet must have at least 1 answer
                    total_claimed += an;
                }
                // Total claimed answers must equal total known answers we passed in
                REQUIRE(total_claimed == static_cast<uint32_t>(known.size()));
            }
        }
    }
}

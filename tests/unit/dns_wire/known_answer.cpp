#include "helpers.h"

using mdnspp::detail::build_dns_query;
using mdnspp::detail::append_known_answer;

static void check_known_answer_appended(const std::vector<std::byte> &pkt)
{
    THEN("the packet is longer than a basic query")
    {
        auto basic = build_dns_query("_http._tcp.local", mdnspp::dns_type::ptr);
        REQUIRE(pkt.size() > basic.size());
    }

    THEN("walk_dns_frame can parse the known-answer PTR record")
    {
        auto parseable = pkt;
        auto records = parse_wire(pkt);
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

SCENARIO("build_dns_query with known answers includes Answer section", "[dns_wire][known_answer]")
{
    GIVEN("a PTR record as a known answer")
    {
        std::vector<mdnspp::mdns_record_variant> known = {
            make_ptr_record("_http._tcp.local", "MyService._http._tcp.local")};

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

            check_known_answer_appended(pkt);
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

#include "helpers.h"

using mdnspp::detail::build_dns_query;
using mdnspp::detail::build_dns_query_tc;

using answers = std::vector<mdnspp::mdns_record_variant>;

static std::string unencodable_name()
{
    return std::string(64, 'a') + ".local.";
}

static mdnspp::record_a make_a_record(std::string address)
{
    mdnspp::record_a a;
    a.name = "host.local.";
    a.ttl = 120;
    a.address_string = std::move(address);
    return a;
}

SCENARIO("build_dns_query with known answers returns no packet for a name that fails to encode",
         "[dns_wire][known_answer][error_handling]")
{
    GIVEN("a query name with a 64-character label")
    {
        THEN("no known answers give an empty packet")
        {
            REQUIRE(build_dns_query(unencodable_name(), mdnspp::dns_type::ptr, answers{}).empty());
        }

        THEN("an encodable known answer still gives an empty packet")
        {
            answers known = {make_a_record("192.168.1.10")};
            REQUIRE(build_dns_query(unencodable_name(), mdnspp::dns_type::ptr, known).empty());
        }
    }
}

SCENARIO("build_dns_query_tc returns no packets for a name that fails to encode",
         "[dns_wire][tc][known_answer][error_handling]")
{
    GIVEN("a query name with a 64-character label")
    {
        THEN("no known answers give no packets")
        {
            REQUIRE(build_dns_query_tc(unencodable_name(), mdnspp::dns_type::ptr, answers{}).empty());
        }

        THEN("known answers that all fail to encode give no packets")
        {
            answers known = {make_a_record("999.1.2.3"), make_a_record("not-an-address")};
            REQUIRE(build_dns_query_tc(unencodable_name(), mdnspp::dns_type::ptr, known).empty());
        }

        THEN("encodable known answers give no packets")
        {
            answers known = {make_a_record("192.168.1.10"), make_a_record("192.168.1.11")};
            REQUIRE(build_dns_query_tc(unencodable_name(), mdnspp::dns_type::ptr, known).empty());
        }
    }
}

SCENARIO("build_dns_query_tc counts only the known answers that encoded",
         "[dns_wire][tc][known_answer][error_handling]")
{
    GIVEN("one known answer that fails to encode and one that encodes")
    {
        answers known = {make_a_record("999.1.2.3"), make_a_record("192.168.1.10")};
        auto packets = build_dns_query_tc("_http._tcp.local.", mdnspp::dns_type::ptr, known);

        THEN("one packet carries ANCOUNT 1")
        {
            REQUIRE(packets.size() == 1);
            REQUIRE(packets[0].size() >= 12);
            REQUIRE(::read_u16_be(packets[0], 6) == 1);
        }
    }
}

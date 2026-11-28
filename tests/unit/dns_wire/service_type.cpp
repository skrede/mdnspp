#include "helpers.h"

using mdnspp::parse_service_type;

static void check_rejected(std::string_view given, std::string_view name)
{
    GIVEN(given)
    {
        auto result = mdnspp::parse_service_type_checked(name);

        THEN("parsing fails with invalid_name")
        {
            REQUIRE_FALSE(result.has_value());
            REQUIRE(result.error() == mdnspp::mdns_error::invalid_name);
        }
    }
}

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

SCENARIO("parse_service_type_checked rejects structurally incomplete names",
         "[dns_wire][parse_service_type]")
{
    GIVEN("a complete service type")
    {
        auto result = mdnspp::parse_service_type_checked("_http._tcp.local.");

        THEN("parsing succeeds with all components populated")
        {
            REQUIRE(result.has_value());
            REQUIRE(result->type_name == "_http");
            REQUIRE(result->protocol == "_tcp");
            REQUIRE(result->domain == "local");
        }
    }

    check_rejected("a name missing the domain label", "_http._tcp");
    check_rejected("a single label", "_http");
    check_rejected("an empty label between dots", "_http..local");
    check_rejected("an empty string", "");
}

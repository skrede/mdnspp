#include "mdnspp/service_type.h"

#include <catch2/catch_test_macros.hpp>

#include <string_view>

using mdnspp::mdns_error;
using mdnspp::parse_service_type;
using mdnspp::parse_service_type_checked;

namespace {

void require_fields(std::string_view name, std::string_view full, std::string_view type_name,
                    std::string_view protocol, std::string_view domain)
{
    INFO("name: \"" << name << "\"");
    const auto info = parse_service_type(name);
    REQUIRE(info.service_type == full);
    REQUIRE(info.type_name == type_name);
    REQUIRE(info.protocol == protocol);
    REQUIRE(info.domain == domain);
}

void require_rejected(std::string_view name)
{
    INFO("name: \"" << name << "\"");
    const auto result = parse_service_type_checked(name);
    REQUIRE_FALSE(result.has_value());
    REQUIRE(result.error() == mdns_error::invalid_name);
}

}

TEST_CASE("parse_service_type splits a complete service type", "[service_type]")
{
    require_fields("_http._tcp.local", "_http._tcp.local", "_http", "_tcp", "local");
    require_fields("_ipp._tcp.local.", "_ipp._tcp.local", "_ipp", "_tcp", "local");
    require_fields("_http._tcp.example.com", "_http._tcp.example.com", "_http", "_tcp", "example.com");
}

TEST_CASE("parse_service_type leaves missing labels empty", "[service_type]")
{
    require_fields("_http", "_http", "", "", "");
    require_fields("_http._tcp", "_http._tcp", "_http", "_tcp", "");
    require_fields("._tcp.local", "._tcp.local", "", "_tcp", "local");
    require_fields("", "", "", "", "");
    require_fields(".", "", "", "", "");
}

TEST_CASE("parse_service_type_checked rejects an incomplete service type", "[service_type]")
{
    require_rejected("_http");
    require_rejected("_http._tcp");
    require_rejected("._tcp.local");
    require_rejected("");
    require_rejected(".");
}

TEST_CASE("parse_service_type_checked accepts a complete service type", "[service_type]")
{
    for(std::string_view name : {"_http._tcp.local", "_ipp._tcp.local.", "_http._tcp.example.com"})
    {
        INFO("name: \"" << name << "\"");
        const auto result = parse_service_type_checked(name);
        REQUIRE(result.has_value());
        REQUIRE(result->service_type == parse_service_type(name).service_type);
    }
}

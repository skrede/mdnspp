#include "mdnspp/detail/validate_multicast.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <system_error>

using mdnspp::detail::validate_multicast_address;

TEST_CASE("validate_multicast_address accepts IPv4 multicast (224.0.0.0/4)", "[validate_multicast]")
{
    std::error_code ec;
    for(const std::string address : {"224.0.0.251", "224.0.0.0", "239.255.255.255", "230.1.2.3"})
    {
        validate_multicast_address(address, ec);
        INFO(address);
        REQUIRE_FALSE(ec);
    }
}

TEST_CASE("validate_multicast_address rejects IPv4 unicast and out-of-range addresses", "[validate_multicast]")
{
    std::error_code ec;
    for(const std::string address : {"192.168.1.1", "223.255.255.255", "240.0.0.1", "127.0.0.1", "0.0.0.0"})
    {
        validate_multicast_address(address, ec);
        INFO(address);
        REQUIRE(ec == std::errc::invalid_argument);
    }
}

TEST_CASE("validate_multicast_address accepts IPv6 multicast (ff00::/8)", "[validate_multicast]")
{
    std::error_code ec;
    for(const std::string address : {"ff02::fb", "ff05::1", "ff00::"})
    {
        validate_multicast_address(address, ec);
        INFO(address);
        REQUIRE_FALSE(ec);
    }
}

TEST_CASE("validate_multicast_address rejects IPv6 non-multicast addresses", "[validate_multicast]")
{
    std::error_code ec;
    for(const std::string address : {"::1", "fe80::1", "2001:db8::1"})
    {
        validate_multicast_address(address, ec);
        INFO(address);
        REQUIRE(ec == std::errc::invalid_argument);
    }
}

TEST_CASE("validate_multicast_address rejects empty and malformed input", "[validate_multicast]")
{
    std::error_code ec;
    for(const std::string address : {"", "not-an-address", "224.0.0", "224.0.0.251.1"})
    {
        validate_multicast_address(address, ec);
        INFO(address);
        REQUIRE(ec == std::errc::invalid_argument);
    }
}

TEST_CASE("validate_multicast_address clears a previously-set error code on success", "[validate_multicast]")
{
    std::error_code ec = std::make_error_code(std::errc::io_error);
    validate_multicast_address("224.0.0.251", ec);
    REQUIRE_FALSE(ec);
}

TEST_CASE("validate_multicast_address throwing overload", "[validate_multicast]")
{
    REQUIRE_NOTHROW(validate_multicast_address("224.0.0.251"));
    REQUIRE_THROWS_AS(validate_multicast_address("192.168.1.1"), std::system_error);
}

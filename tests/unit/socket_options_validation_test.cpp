#include "mdnspp/socket_options.h"

#include "mdnspp/detail/validate_multicast.h"

#include "mdnspp/default/default_socket.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <system_error>

using namespace mdnspp;

TEST_CASE("validate_multicast_address accepts default mDNS address", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("224.0.0.251", ec);
    REQUIRE_FALSE(ec);
}

TEST_CASE("validate_multicast_address accepts custom IPv4 multicast", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("239.1.2.3", ec);
    REQUIRE_FALSE(ec);
}

TEST_CASE("validate_multicast_address accepts low multicast boundary", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("224.0.0.0", ec);
    REQUIRE_FALSE(ec);
}

TEST_CASE("validate_multicast_address accepts high multicast boundary", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("239.255.255.255", ec);
    REQUIRE_FALSE(ec);
}

TEST_CASE("validate_multicast_address rejects unicast address", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("10.0.0.1", ec);
    REQUIRE(ec);
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("validate_multicast_address rejects address just below multicast range", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("223.255.255.255", ec);
    REQUIRE(ec);
}

TEST_CASE("validate_multicast_address rejects address just above multicast range", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("240.0.0.0", ec);
    REQUIRE(ec);
}

TEST_CASE("validate_multicast_address rejects empty address", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("", ec);
    REQUIRE(ec);
}

TEST_CASE("validate_multicast_address rejects garbage string", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("not-an-address", ec);
    REQUIRE(ec);
}

TEST_CASE("validate_multicast_address accepts IPv6 multicast", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("ff02::fb", ec);
    REQUIRE_FALSE(ec);
}

TEST_CASE("validate_multicast_address rejects IPv6 unicast", "[socket_options][validation]")
{
    std::error_code ec;
    mdnspp::detail::validate_multicast_address("::1", ec);
    REQUIRE(ec);
}

TEST_CASE("validate_multicast_address throwing overload throws on unicast", "[socket_options][validation]")
{
    REQUIRE_THROWS_AS(
        mdnspp::detail::validate_multicast_address("10.0.0.1"),
        std::system_error);
}

TEST_CASE("validate_multicast_address throwing overload succeeds on multicast", "[socket_options][validation]")
{
    REQUIRE_NOTHROW(mdnspp::detail::validate_multicast_address("224.0.0.251"));
}

TEST_CASE("default_socket rejects an unknown interface_name", "[socket_options][interface]")
{
    default_context ctx;
    socket_options opts{.interface_name = "mdnspp-nonexistent0"};

    std::error_code ec;
    default_socket sock{ctx, opts, ec};
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("default_socket rejects an unknown interface_index", "[socket_options][interface]")
{
    default_context ctx;
    socket_options opts{.interface_index = uint32_t{0xFFFFFFF0}};

    std::error_code ec;
    default_socket sock{ctx, opts, ec};
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("default_socket throwing constructor reports an unknown interface_name", "[socket_options][interface]")
{
    default_context ctx;
    socket_options opts{.interface_name = "mdnspp-nonexistent0"};
    REQUIRE_THROWS_AS((default_socket{ctx, opts}), std::system_error);
}

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/testing/mock_policy.h"
#include "mdnspp/detail/validate_multicast.h"

#include <catch2/catch_test_macros.hpp>

#include <system_error>

using namespace mdnspp;
using namespace mdnspp::testing;

TEST_CASE("Default socket_options has empty interface_address", "[socket_options]")
{
    REQUIRE(socket_options{}.interface_address.empty());
}

TEST_CASE("Default socket_options has loopback enabled", "[socket_options]")
{
    REQUIRE(socket_options{}.multicast_loopback == loopback_mode::enabled);
}

TEST_CASE("Default socket_options has nullopt multicast_ttl", "[socket_options]")
{
    REQUIRE_FALSE(socket_options{}.multicast_ttl.has_value());
}

TEST_CASE("loopback_mode enum values", "[socket_options]")
{
    REQUIRE(loopback_mode::enabled != loopback_mode::disabled);
}

TEST_CASE("MockSocket stores socket_options", "[socket_options][mock]")
{
    mock_executor ex;
    socket_options opts{
        .interface_address = "192.168.1.1",
        .multicast_loopback = loopback_mode::disabled,
        .multicast_ttl = uint8_t{255}
    };

    MockSocket mock{ex, opts};
    REQUIRE(mock.options().interface_address == "192.168.1.1");
    REQUIRE(mock.options().multicast_loopback == loopback_mode::disabled);
    REQUIRE(mock.options().multicast_ttl == uint8_t{255});
}

TEST_CASE("MockSocket socket_options with error_code", "[socket_options][mock]")
{
    mock_executor ex;
    socket_options opts{.interface_address = "10.0.0.1"};

    SECTION("success path stores options")
    {
        std::error_code ec;
        MockSocket mock{ex, opts, ec};
        REQUIRE_FALSE(ec);
        REQUIRE(mock.options().interface_address == "10.0.0.1");
    }

    SECTION("failure path sets error_code")
    {
        MockSocket::set_fail_on_construct(true);
        std::error_code ec;
        MockSocket mock{ex, opts, ec};
        REQUIRE(ec);
        MockSocket::set_fail_on_construct(false);
    }
}

TEST_CASE("socket_options multicast_ttl value_or defaults to 255", "[socket_options]")
{
    REQUIRE(socket_options{}.multicast_ttl.value_or(uint8_t{255}) == uint8_t{255});
    REQUIRE(socket_options{.multicast_ttl = uint8_t{1}}.multicast_ttl.value_or(uint8_t{255}) == uint8_t{1});
}

TEST_CASE("Default socket_options has standard mDNS multicast_group", "[socket_options]")
{
    auto opts = socket_options{};
    REQUIRE(opts.multicast_group == endpoint{"224.0.0.251", 5353});
}

TEST_CASE("socket_options multicast_group accepts custom values", "[socket_options]")
{
    auto opts = socket_options{.multicast_group = {"239.1.2.3", 5354}};
    REQUIRE(opts.multicast_group.address == "239.1.2.3");
    REQUIRE(opts.multicast_group.port == 5354);
}

TEST_CASE("socket_options multicast_group comparison uses operator<=>", "[socket_options]")
{
    endpoint default_ep{"224.0.0.251", 5353};
    endpoint custom_ep{"239.1.2.3", 5354};

    REQUIRE(socket_options{}.multicast_group == default_ep);
    REQUIRE(socket_options{}.multicast_group != custom_ep);
    REQUIRE(socket_options{.multicast_group = custom_ep}.multicast_group == custom_ep);
}

// --- Multicast address validation tests ---

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

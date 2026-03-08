#include "mdnspp/socket_options.h"
#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

using namespace mdnspp;
using namespace mdnspp::testing;

TEST_CASE("Default socket_options has empty interface_address", "[socket_options]")
{
    REQUIRE(socket_options{}.interface_address.empty());
}

TEST_CASE("Default socket_options has nullopt multicast_loopback", "[socket_options]")
{
    REQUIRE_FALSE(socket_options{}.multicast_loopback.has_value());
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

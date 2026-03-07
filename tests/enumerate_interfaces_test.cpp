#include "mdnspp/network_interface.h"

#include <catch2/catch_test_macros.hpp>

using namespace mdnspp;

TEST_CASE("enumerate_interfaces returns at least one interface", "[enumerate][interface]")
{
    auto ifs = enumerate_interfaces();
    REQUIRE_FALSE(ifs.empty());
}

TEST_CASE("enumerate_interfaces returns loopback", "[enumerate][interface]")
{
    auto ifs = enumerate_interfaces();
    auto it = std::ranges::find_if(ifs, [](const auto &iface) { return iface.is_loopback; });
    REQUIRE(it != ifs.end());
}

TEST_CASE("network_interface fields are populated", "[enumerate][interface]")
{
    auto ifs = enumerate_interfaces();
    for (const auto &iface : ifs)
    {
        REQUIRE_FALSE(iface.name.empty());
        REQUIRE(iface.index > 0);
    }
}

TEST_CASE("enumerate_interfaces non-throwing overload", "[enumerate][interface]")
{
    std::error_code ec;
    auto ifs = enumerate_interfaces(ec);
    REQUIRE_FALSE(ec);
    REQUIRE_FALSE(ifs.empty());
}

TEST_CASE("loopback interface has ipv4_address", "[enumerate][interface]")
{
    auto ifs = enumerate_interfaces();
    auto it = std::ranges::find_if(ifs, [](const auto &iface) { return iface.is_loopback; });
    REQUIRE(it != ifs.end());
    REQUIRE(it->ipv4_address == "127.0.0.1");
}

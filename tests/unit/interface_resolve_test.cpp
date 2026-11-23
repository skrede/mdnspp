#include "interface_resolve_fixture.h"

#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/interface_resolve.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstdint>
#include <system_error>

using namespace mdnspp;
using namespace mdnspp::detail;

TEST_CASE("extract_interface_binding reads socket_options binding fields", "[interface_resolve]")
{
    socket_options opts{
        .interface_address = "10.0.0.2",
        .interface_name = "eth0",
        .interface_index = uint32_t{2},
    };
    auto binding = extract_interface_binding(opts);
    REQUIRE(binding.index == uint32_t{2});
    REQUIRE(binding.name == "eth0");
    REQUIRE(binding.address == "10.0.0.2");
    REQUIRE(binding.bound());

    REQUIRE_FALSE(extract_interface_binding(socket_options{}).bound());
}

TEST_CASE("find_interface matches by index, name, then address", "[interface_resolve]")
{
    auto nics = test_interfaces();

    REQUIRE(find_interface(nics, {.index = 3})->name == "eth1");
    REQUIRE(find_interface(nics, {.name = "wlan0"})->index == 4);
    REQUIRE(find_interface(nics, {.address = "10.0.1.3"})->name == "eth1");
    REQUIRE(find_interface(nics, {.address = "fe80::4"})->name == "wlan0");
    REQUIRE(find_interface(nics, {}) == nullptr);
}

TEST_CASE("find_interface index takes precedence over name and address", "[interface_resolve]")
{
    auto nics = test_interfaces();

    auto *nic = find_interface(nics, {.index = 2, .name = "eth1", .address = "fe80::4"});
    REQUIRE(nic != nullptr);
    REQUIRE(nic->name == "eth0");

    REQUIRE(find_interface(nics, {.index = 99, .name = "eth0"}) == nullptr);

    REQUIRE(find_interface(nics, {.name = "eth1", .address = "10.0.0.2"})->name == "eth1");
    REQUIRE(find_interface(nics, {.name = "nope", .address = "10.0.0.2"}) == nullptr);
}

TEST_CASE("find_interface matches a binding address against every address of an interface", "[interface_resolve]")
{
    network_interface multi = make_nic(6, "eth3", "192.0.2.6", "2001:db8::6");
    multi.addresses.push_back({*parse_ip_address("198.51.100.6"), 24});
    multi.addresses.push_back({*parse_ip_address("fe80::6"), 64});
    std::vector<network_interface> nics = test_interfaces();
    nics.push_back(multi);

    REQUIRE(find_interface(nics, {.address = "198.51.100.6"})->name == "eth3");
    REQUIRE(find_interface(nics, {.address = "fe80::6"})->name == "eth3");
    REQUIRE(find_interface(nics, {.address = "192.0.2.99"}) == nullptr);
    REQUIRE(find_interface(nics, {.address = "not an address"}) == nullptr);
}

TEST_CASE("select_interface_address resolves name and index to the family address", "[interface_resolve]")
{
    auto nics = test_interfaces();
    std::error_code ec;

    REQUIRE(select_interface_address(nics, {.name = "eth0"}, false, ec) == "10.0.0.2");
    REQUIRE_FALSE(ec);
    REQUIRE(select_interface_address(nics, {.name = "eth0"}, true, ec) == "fe80::2");
    REQUIRE_FALSE(ec);
    REQUIRE(select_interface_address(nics, {.index = 4}, true, ec) == "fe80::4");
    REQUIRE_FALSE(ec);
}

TEST_CASE("select_interface_address fails for unknown name or index", "[interface_resolve]")
{
    auto nics = test_interfaces();
    std::error_code ec;

    REQUIRE(select_interface_address(nics, {.name = "nope0"}, false, ec).empty());
    REQUIRE(ec == std::errc::invalid_argument);

    REQUIRE(select_interface_address(nics, {.index = 99}, false, ec).empty());
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("select_interface_address fails when the interface lacks the family", "[interface_resolve]")
{
    auto nics = test_interfaces();
    std::error_code ec;

    REQUIRE(select_interface_address(nics, {.name = "eth1"}, true, ec).empty());
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("select_interface_address passes a plain address binding through", "[interface_resolve]")
{
    auto nics = test_interfaces();
    std::error_code ec;

    REQUIRE(select_interface_address(nics, {.address = "192.0.2.7"}, false, ec) == "192.0.2.7");
    REQUIRE_FALSE(ec);
    REQUIRE(select_interface_address(nics, {}, false, ec).empty());
    REQUIRE_FALSE(ec);
}

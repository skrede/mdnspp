// tests/interface_resolve_test.cpp
//
// detail/interface_resolve.h over synthetic interface lists: binding
// extraction, index > name > address precedence, socket address selection
// errors, and RFC 6762 §6.2 advertised-address resolution. Socket-level
// coverage of the same precedence lives in socket_options_test.cpp.

#include "mdnspp/service_info.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/interface_resolve.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <cstdint>
#include <system_error>

using namespace mdnspp;
using namespace mdnspp::detail;

namespace {

network_interface make_nic(uint32_t index, std::string name,
                           std::string ipv4 = {}, std::string ipv6 = {},
                           bool loopback = false, bool up = true)
{
    network_interface nic;
    nic.name = std::move(name);
    nic.ipv4_address = std::move(ipv4);
    nic.ipv6_address = std::move(ipv6);
    nic.index = index;
    nic.is_loopback = loopback;
    nic.is_up = up;
    return nic;
}

std::vector<network_interface> test_interfaces()
{
    return {
        make_nic(1, "lo", "127.0.0.1", "::1", true),
        make_nic(2, "eth0", "10.0.0.2", "fe80::2"),
        make_nic(3, "eth1", "10.0.1.3"),               // no IPv6
        make_nic(4, "wlan0", {}, "fe80::4"),           // no IPv4
        make_nic(5, "eth2", "10.0.2.5", {}, false, false), // down
    };
}

}

// ---------------------------------------------------------------------------
// extract_interface_binding
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// find_interface — precedence
// ---------------------------------------------------------------------------

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

    // index wins even when name and address designate other interfaces
    auto *nic = find_interface(nics, {.index = 2, .name = "eth1", .address = "fe80::4"});
    REQUIRE(nic != nullptr);
    REQUIRE(nic->name == "eth0");

    // an unmatched index is final — no fallback to the matching name
    REQUIRE(find_interface(nics, {.index = 99, .name = "eth0"}) == nullptr);

    // name wins over address; an unmatched name does not fall back to address
    REQUIRE(find_interface(nics, {.name = "eth1", .address = "10.0.0.2"})->name == "eth1");
    REQUIRE(find_interface(nics, {.name = "nope", .address = "10.0.0.2"}) == nullptr);
}

// ---------------------------------------------------------------------------
// select_interface_address — the socket open path
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// resolve_advertised_addresses — RFC 6762 §6.2
// ---------------------------------------------------------------------------

TEST_CASE("resolve_advertised_addresses is a no-op without auto_address", "[interface_resolve]")
{
    service_info info;
    resolve_advertised_addresses(test_interfaces(), {}, info);
    REQUIRE_FALSE(info.address_ipv4.has_value());
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses uses the bound interface", "[interface_resolve]")
{
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(test_interfaces(), {.index = 2}, info);
    REQUIRE(info.address_ipv4 == "10.0.0.2");
    REQUIRE(info.address_ipv6 == "fe80::2");
}

TEST_CASE("resolve_advertised_addresses never crosses interfaces for a missing family", "[interface_resolve]")
{
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(test_interfaces(), {.name = "eth1"}, info);
    REQUIRE(info.address_ipv4 == "10.0.1.3");
    REQUIRE_FALSE(info.address_ipv6.has_value()); // eth1 has no IPv6
}

TEST_CASE("resolve_advertised_addresses preserves user-set fields", "[interface_resolve]")
{
    service_info info;
    info.auto_address = true;
    info.address_ipv4 = "192.0.2.1";
    resolve_advertised_addresses(test_interfaces(), {.index = 2}, info);
    REQUIRE(info.address_ipv4 == "192.0.2.1");
    REQUIRE(info.address_ipv6 == "fe80::2");
}

TEST_CASE("resolve_advertised_addresses uses an address-only binding verbatim", "[interface_resolve]")
{
    // The bound link is not in the enumerated list (e.g. an inproc or
    // container interface): the binding address itself is the announcing
    // link's address for its family.
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(test_interfaces(), {.address = "172.16.0.9"}, info);
    REQUIRE(info.address_ipv4 == "172.16.0.9");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

TEST_CASE("resolve_advertised_addresses unbound falls back to the lowest-index candidate", "[interface_resolve]")
{
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(test_interfaces(), {}, info);
    // Skips lo (loopback) and eth2 (down); eth0 (index 2) wins IPv4 and IPv6.
    REQUIRE(info.address_ipv4 == "10.0.0.2");
    REQUIRE(info.address_ipv6 == "fe80::2");
}

TEST_CASE("resolve_advertised_addresses leaves a family with no candidate unset", "[interface_resolve]")
{
    std::vector<network_interface> v4_only{
        make_nic(1, "lo", "127.0.0.1", "::1", true),
        make_nic(2, "eth0", "10.0.0.2"),
    };
    service_info info;
    info.auto_address = true;
    resolve_advertised_addresses(v4_only, {}, info);
    REQUIRE(info.address_ipv4 == "10.0.0.2");
    REQUIRE_FALSE(info.address_ipv6.has_value());
}

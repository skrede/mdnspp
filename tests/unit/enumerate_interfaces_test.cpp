#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/ip_address_ops.h"
#include "mdnspp/detail/interface_addresses.h"

#include "support/skip_or_fail.h"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <algorithm>
#include <string_view>

using namespace mdnspp;

namespace {

ip_network network(std::string_view text, uint8_t prefix_length)
{
    return {*detail::parse_ip_address(text), prefix_length};
}

bool reports(const network_interface &nic, const ip_network &expected)
{
    return std::ranges::find(nic.addresses, expected) != nic.addresses.end();
}

}

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

TEST_CASE("loopback interface reports 127.0.0.1/8 and ::1/128", "[enumerate][interface]")
{
    auto ifs = enumerate_interfaces();
    auto it = std::ranges::find_if(ifs, [](const auto &iface) { return iface.is_loopback; });
    REQUIRE(it != ifs.end());
    REQUIRE(reports(*it, network("127.0.0.1", 8)));
    if(!detail::has_family(*it, address_family::ipv6))
        test_support::skip_or_fail("the loopback interface has no IPv6 address");
    REQUIRE(reports(*it, network("::1", 128)));
}

TEST_CASE("enumerate_interfaces reports every interface's addresses sorted", "[enumerate][interface]")
{
    for(const network_interface &nic : enumerate_interfaces())
    {
        INFO(nic.name);
        REQUIRE(std::ranges::is_sorted(nic.addresses, detail::address_before));
    }
}

#ifdef __APPLE__
TEST_CASE("enumerate_interfaces reports link-local addresses without an embedded scope", "[enumerate][interface]")
{
    int32_t link_local = 0;
    for(const network_interface &nic : enumerate_interfaces())
        for(const ip_network &net : nic.addresses)
        {
            const auto &bytes = net.address.bytes;
            if(net.address.family != address_family::ipv6 || bytes[0] != std::byte{0xFE} ||
               (bytes[1] & std::byte{0xC0}) != std::byte{0x80})
                continue;
            ++link_local;
            INFO(nic.name << " " << detail::format_ip_address(net.address));
            CHECK(bytes[2] == std::byte{0});
            CHECK(bytes[3] == std::byte{0});
        }
    if(link_local == 0)
        test_support::skip_or_fail("no interface has a link-local IPv6 address");
}
#endif

#include "mdnspp/ip_address.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/detail/nic_diff.h"
#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <algorithm>
#include <string_view>

using namespace mdnspp;
using namespace mdnspp::detail;

namespace {

ip_network network(std::string_view text, uint8_t prefix_length)
{
    return {*parse_ip_address(text), prefix_length};
}

network_interface dual_stack_nic()
{
    network_interface nic;
    nic.name = "nic1";
    nic.index = 1;
    nic.is_up = true;
    nic.addresses = {network("192.0.2.1", 24), network("2001:db8::1", 64)};
    return nic;
}

}

TEST_CASE("nic_changed reports a changed first address or a gained or lost family", "[nic_monitor]")
{
    const network_interface before = dual_stack_nic();
    network_interface changed = before;
    changed.addresses[0] = network("192.0.2.2", 24);
    network_interface lost_family = before;
    lost_family.addresses.pop_back();
    network_interface gained_family = lost_family;
    gained_family.addresses.erase(gained_family.addresses.begin());

    CHECK(nic_changed(before, changed));
    CHECK(nic_changed(before, lost_family));
    CHECK(nic_changed(lost_family, before));
    CHECK(nic_changed(lost_family, gained_family));
    CHECK_FALSE(nic_changed(before, dual_stack_nic()));
}

TEST_CASE("nic_changed ignores an address added or removed after the first of its family", "[nic_monitor]")
{
    const network_interface before = dual_stack_nic();
    network_interface added = before;
    added.addresses.push_back(network("2001:db8::2", 64));
    added.addresses.push_back(network("192.0.2.9", 24));
    network_interface rotated = added;
    rotated.addresses.erase(rotated.addresses.begin() + 2);

    CHECK_FALSE(nic_changed(before, added));
    CHECK_FALSE(nic_changed(added, before));
    CHECK_FALSE(nic_changed(added, rotated));
    CHECK(diff_nics(std::vector{before}, std::vector{added}).empty());
}

TEST_CASE("nic_changed follows the first address that link-local selection picks", "[nic_monitor]")
{
    network_interface link_local_only = dual_stack_nic();
    link_local_only.addresses[0] = network("169.254.1.1", 16);
    network_interface routable_added = link_local_only;
    routable_added.addresses.push_back(network("192.0.2.1", 24));

    CHECK(nic_changed(link_local_only, routable_added));
    CHECK(nic_changed(routable_added, link_local_only));
}

TEST_CASE("nic_changed reports a changed prefix length", "[nic_monitor]")
{
    const network_interface before = dual_stack_nic();
    network_interface widened = before;
    widened.addresses[0].prefix_length = 16;
    CHECK(nic_changed(before, widened));
}

TEST_CASE("nic_changed reports a changed up state", "[nic_monitor]")
{
    const network_interface before = dual_stack_nic();
    network_interface down = before;
    down.is_up = false;
    CHECK(nic_changed(before, down));
}

TEST_CASE("a reordering of an interface's addresses is not a change", "[nic_monitor]")
{
    const network_interface before = dual_stack_nic();
    network_interface reordered = before;
    std::ranges::reverse(reordered.addresses);

    CHECK_FALSE(nic_changed(before, reordered));
    CHECK(diff_nics(std::vector{before}, std::vector{reordered}).empty());
}

TEST_CASE("diff_nics reports a prefix change as a removal followed by an addition", "[nic_monitor]")
{
    const network_interface before = dual_stack_nic();
    network_interface widened = before;
    widened.addresses[1].prefix_length = 48;

    const std::vector<nic_change> changes = diff_nics(std::vector{before}, std::vector{widened});
    REQUIRE(changes.size() == 2);
    CHECK(changes[0].kind == nic_change_kind::removed);
    CHECK(changes[0].iface.addresses == before.addresses);
    CHECK(changes[1].kind == nic_change_kind::added);
    CHECK(changes[1].iface.addresses == widened.addresses);
}

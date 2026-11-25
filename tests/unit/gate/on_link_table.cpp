#include "interfaces.h"

#include "mdnspp/detail/policy_clock.h"
#include "mdnspp/detail/on_link_table.h"
#include "mdnspp/detail/ip_address_ops.h"

#include "mdnspp/inproc/inproc_policy.h"

#include "mdnspp/testing/test_clock.h"
#include "mdnspp/testing/mock_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <type_traits>

using mdnspp::testing::test_clock;
using namespace std::chrono_literals;

namespace {

using table = mdnspp::detail::on_link_table<test_clock>;

bool on_link(table &t, const char *source, uint32_t recv_ifindex, uint32_t bound_ifindex = 0)
{
    return t.on_link(*mdnspp::detail::parse_ip_address(source), recv_ifindex, bound_ifindex);
}

interface_snapshot two_subnets()
{
    return interface_snapshot{
        {nic_with(2, {network_of("192.0.2.1", 24)}), nic_with(3, {network_of("203.0.113.5", 24)})}};
}

}

static_assert(std::is_same_v<mdnspp::detail::policy_clock_t<mdnspp::inproc_test_policy>, test_clock>);
static_assert(std::is_same_v<mdnspp::detail::policy_clock_t<mdnspp::testing::mock_policy>, std::chrono::steady_clock>);

TEST_CASE("on_link_table tests a source against the prefixes of the receiving interface", "[gate][on-link]")
{
    test_clock::reset();
    interface_snapshot snapshot{{nic_with(2, {network_of("192.0.2.1", 24), network_of("2001:db8:1::1", 64)}),
                                 nic_with(4, {network_of("198.51.100.1", 27), network_of("2001:db8:0:80::1", 57)})}};
    table t{enumerate_from(snapshot)};
    CHECK(on_link(t, "192.0.2.77", 2));
    CHECK_FALSE(on_link(t, "192.0.3.77", 2));
    CHECK(on_link(t, "2001:db8:1::99", 2));
    CHECK_FALSE(on_link(t, "2001:db8:2::1", 2));
    CHECK(on_link(t, "198.51.100.30", 4));
    CHECK_FALSE(on_link(t, "198.51.100.33", 4));
    CHECK(on_link(t, "2001:db8:0:ff::1", 4));
    CHECK_FALSE(on_link(t, "2001:db8:0:7f::1", 4));
}

TEST_CASE("on_link_table never lets a zero-length prefix match a source", "[gate][on-link]")
{
    test_clock::reset();
    interface_snapshot snapshot{{nic_with(2, {network_of("192.0.2.1", 0), network_of("2001:db8:1::1", 0)})}};
    table t{enumerate_from(snapshot)};
    CHECK_FALSE(on_link(t, "198.51.100.7", 2));
    CHECK_FALSE(on_link(t, "2001:db8:2::1", 2));
    CHECK(on_link(t, "192.0.2.1", 2));
}

TEST_CASE("on_link_table counts an address of any local interface as on-link", "[gate][on-link]")
{
    test_clock::reset();
    interface_snapshot snapshot = two_subnets();
    table t{enumerate_from(snapshot)};
    CHECK(on_link(t, "203.0.113.5", 2));
    CHECK_FALSE(on_link(t, "203.0.113.6", 2));
}

TEST_CASE("on_link_table selects the receiving interface, then the bound one, then every interface", "[gate][on-link]")
{
    test_clock::reset();
    interface_snapshot snapshot = two_subnets();
    table t{enumerate_from(snapshot)};
    CHECK(on_link(t, "203.0.113.6", 3, 2));
    CHECK_FALSE(on_link(t, "192.0.2.7", 3, 2));
    CHECK(on_link(t, "203.0.113.6", 0, 3));
    CHECK_FALSE(on_link(t, "192.0.2.7", 0, 3));
    CHECK(on_link(t, "203.0.113.6", 0, 0));
    CHECK(on_link(t, "192.0.2.7", 0, 0));
    CHECK_FALSE(on_link(t, "192.0.2.7", 9, 0));
}

TEST_CASE("on_link_table enumerates on a miss at most once per second", "[gate][on-link]")
{
    test_clock::reset();
    interface_snapshot snapshot = two_subnets();
    table t{enumerate_from(snapshot)};
    CHECK_FALSE(on_link(t, "198.51.100.7", 2));
    CHECK(snapshot.calls == 1);
    snapshot.interfaces.push_back(nic_with(5, {network_of("198.51.100.1", 24)}));
    test_clock::advance(999ms);
    CHECK_FALSE(on_link(t, "198.51.100.7", 0));
    CHECK(on_link(t, "192.0.2.7", 2));
    CHECK(snapshot.calls == 1);
    test_clock::advance(1ms);
    CHECK(on_link(t, "198.51.100.7", 0));
    CHECK(snapshot.calls == 2);
}

TEST_CASE("on_link_table keeps its snapshot when enumeration fails", "[gate][on-link]")
{
    test_clock::reset();
    interface_snapshot snapshot = two_subnets();
    table t{enumerate_from(snapshot)};
    CHECK(on_link(t, "192.0.2.7", 2));
    snapshot.fail = true;
    test_clock::advance(1s);
    CHECK_FALSE(on_link(t, "198.51.100.7", 2));
    CHECK(snapshot.calls == 2);
    CHECK(on_link(t, "192.0.2.7", 2));
}

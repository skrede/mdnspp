#include "helpers.h"

#include "support/skip_or_fail.h"
#include "support/ipv6_interface.h"

#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include <cstdint>
#include <system_error>

using mdnspp::test_support::ipv6_group_options;
using mdnspp::test_support::loopback_ipv6_interface;

namespace {

uint32_t selected_interface(const mdnspp::socket_options &opts)
{
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket sock{ctx, opts, ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("IPv6 default_socket construction on loopback failed: " + ec.message());
    return mdnspp::test_support::ipv6_multicast_interface(sock.native_handle());
}

}

TEST_CASE("default_socket rejects an IPv6 interface address assigned to no interface", "[native][socket][ipv6]")
{
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket sock{ctx, ipv6_group_options("2001:db8::dead"), ec};
    REQUIRE(ec == std::errc::invalid_argument);
}

TEST_CASE("default_socket sends IPv6 multicast on the bound interface", "[native][socket][ipv6]")
{
    const uint32_t expected = loopback_ipv6_interface().index;
    REQUIRE(selected_interface(ipv6_group_options("::1")) == expected);
}

TEST_CASE("default_socket binds an IPv6 interface address in any text form", "[native][socket][ipv6]")
{
    const uint32_t expected = loopback_ipv6_interface().index;
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket sock{ctx, ipv6_group_options("0:0:0:0:0:0:0:1"), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("IPv6 default_socket construction on loopback failed: " + ec.message());
    REQUIRE(mdnspp::test_support::ipv6_multicast_interface(sock.native_handle()) == expected);
}

TEST_CASE("default_socket selects the IPv6 loopback interface by index and by name", "[native][socket][ipv6]")
{
    const mdnspp::network_interface loopback = loopback_ipv6_interface();
    mdnspp::socket_options by_index = ipv6_group_options();
    by_index.interface_index = loopback.index;
    mdnspp::socket_options by_name = ipv6_group_options();
    by_name.interface_name = loopback.name;

    CHECK(selected_interface(by_index) == loopback.index);
    CHECK(selected_interface(by_name) == loopback.index);
}

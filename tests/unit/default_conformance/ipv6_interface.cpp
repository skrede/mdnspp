#include "helpers.h"

#include "support/skip_or_fail.h"

#include "mdnspp/socket_options.h"

#include "mdnspp/detail/ipv6_interface_index.h"

#include <string>
#include <cstdint>
#include <system_error>

namespace {

mdnspp::socket_options v6_options(const std::string &iface_address)
{
    return mdnspp::socket_options{
        .interface_address = iface_address,
        .multicast_group = mdnspp::endpoint{"ff02::fb", 0},
    };
}

}

TEST_CASE("default_socket rejects an IPv6 interface address assigned to no interface", "[native][socket][ipv6]")
{
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket sock{ctx, v6_options("2001:db8::dead"), ec};
    REQUIRE(ec == std::errc::invalid_argument);
}

#ifndef _WIN32
TEST_CASE("default_socket sends IPv6 multicast on the bound interface", "[native][socket][ipv6]")
{
    const uint32_t expected = mdnspp::detail::resolve_ipv6_interface_index("::1");
    if(expected == 0)
        mdnspp::test_support::skip_or_fail("no interface carries ::1");

    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket sock{ctx, v6_options("::1"), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("default_socket construction on ::1 failed: " + ec.message());

    uint32_t index = 0;
    socklen_t len = sizeof(index);
    REQUIRE(::getsockopt(sock.native_handle(), IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, &len) == 0);
    REQUIRE(index == expected);
}
#endif

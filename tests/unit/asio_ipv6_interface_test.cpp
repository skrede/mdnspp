#include "support/skip_or_fail.h"

#include "mdnspp/socket_options.h"
#include "mdnspp/asio/asio_policy.h"

#include "mdnspp/detail/native_sockaddr.h"

#include <asio.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>
#include <system_error>

#ifndef _WIN32
#  include <netinet/in.h>
#  include <sys/socket.h>
#endif

namespace {

mdnspp::socket_options v6_options(const std::string &iface_address)
{
    return mdnspp::socket_options{
        .interface_address = iface_address,
        .multicast_group = mdnspp::endpoint{"ff02::fb", 0},
    };
}

}

TEST_CASE("asio_socket rejects an IPv6 interface address assigned to no interface", "[asio][socket][ipv6]")
{
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, v6_options("2001:db8::dead"), ec};
    REQUIRE(ec == std::errc::invalid_argument);
}

#ifndef _WIN32
TEST_CASE("asio_socket sends IPv6 multicast on the bound interface", "[asio][socket][ipv6]")
{
    const uint32_t expected = mdnspp::detail::resolve_ipv6_interface_index("::1");
    if(expected == 0)
        mdnspp::test_support::skip_or_fail("no interface carries ::1");

    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, v6_options("::1"), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("asio_socket construction on ::1 failed: " + ec.message());

    uint32_t index = 0;
    socklen_t len = sizeof(index);
    REQUIRE(::getsockopt(socket.native_handle(), IPPROTO_IPV6, IPV6_MULTICAST_IF, &index, &len) == 0);
    REQUIRE(index == expected);
}
#endif

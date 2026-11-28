#include "support/skip_or_fail.h"
#include "support/ipv6_interface.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"

#include "mdnspp/asio/asio_policy.h"

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/native_sockaddr.h"

#include <asio.hpp>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <system_error>

using mdnspp::test_support::ipv6_group_options;
using mdnspp::test_support::loopback_ipv6_interface;

namespace {

uint32_t selected_interface(const mdnspp::socket_options &opts)
{
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, opts, ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("IPv6 asio_socket construction on loopback failed: " + ec.message());
    return mdnspp::test_support::ipv6_multicast_interface(socket.native_handle());
}

uint32_t bound_interface(const mdnspp::socket_options &opts)
{
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, opts, ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("asio_socket construction failed: " + ec.message());
    return socket.interface_index();
}

#ifndef _WIN32
constexpr uint16_t discard_port = 9;
const std::array<std::byte, 4> payload{};
const std::array<const char *, 4> rejected_destinations{"::1%1x", "fe80::1%3x", "fe80::1%", "fe80::1%nosuchif0"};

std::error_code thrown_by_send(mdnspp::asio_socket &socket, const mdnspp::endpoint &dest)
{
    try
    {
        socket.send(dest, payload);
    }
    catch(const std::system_error &e)
    {
        return e.code();
    }
    return {};
}
#endif

}

TEST_CASE("asio_socket rejects an IPv6 interface address assigned to no interface", "[asio][socket][ipv6]")
{
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, ipv6_group_options("2001:db8::dead"), ec};
    REQUIRE(ec == std::errc::invalid_argument);
    REQUIRE(socket.native_handle() == mdnspp::detail::invalid_socket);
}

TEST_CASE("asio_socket sends IPv6 multicast on the bound interface", "[asio][socket][ipv6]")
{
    const uint32_t expected = loopback_ipv6_interface().index;
    REQUIRE(selected_interface(ipv6_group_options("::1")) == expected);
}

TEST_CASE("asio_socket selects the IPv6 loopback interface by index and by name", "[asio][socket][ipv6]")
{
    const mdnspp::network_interface loopback = loopback_ipv6_interface();
    mdnspp::socket_options by_index = ipv6_group_options();
    by_index.interface_index = loopback.index;
    mdnspp::socket_options by_name = ipv6_group_options();
    by_name.interface_name = loopback.name;

    CHECK(selected_interface(by_index) == loopback.index);
    CHECK(selected_interface(by_name) == loopback.index);
}

TEST_CASE("asio_socket reports the interface index it is bound to", "[asio][socket][ipv6]")
{
    const uint32_t loopback = loopback_ipv6_interface().index;
    mdnspp::socket_options by_index = ipv6_group_options();
    by_index.interface_index = loopback;

    CHECK(bound_interface(by_index) == loopback);
    CHECK(bound_interface(ipv6_group_options("::1")) == loopback);
}

TEST_CASE("an unbound asio_socket reports interface index 0", "[asio][socket]")
{
    CHECK(bound_interface(mdnspp::socket_options{.multicast_group = mdnspp::endpoint{"224.0.0.251", 0}}) == 0);
}

#ifndef _WIN32
TEST_CASE("asio_socket rejects every destination the native parser rejects", "[asio][socket][ipv6]")
{
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, ipv6_group_options("::1"), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("asio_socket construction on ::1 failed: " + ec.message());

    for(const char *text : rejected_destinations)
    {
        CAPTURE(text);
        const mdnspp::endpoint dest{text, discard_port};
        REQUIRE_FALSE(mdnspp::detail::build_sockaddr(dest).has_value());
        socket.send(dest, payload, ec);
        CHECK(ec == std::errc::invalid_argument);
        CHECK(thrown_by_send(socket, dest) == std::errc::invalid_argument);
    }
}

TEST_CASE("asio_socket sends to an IPv6 destination without a zone", "[asio][socket][ipv6]")
{
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, ipv6_group_options("::1"), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("asio_socket construction on ::1 failed: " + ec.message());

    socket.send(mdnspp::endpoint{"::1", discard_port}, payload, ec);
    REQUIRE(ec != std::errc::invalid_argument);
}
#endif

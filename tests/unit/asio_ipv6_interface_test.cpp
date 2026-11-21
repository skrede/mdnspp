#include "support/skip_or_fail.h"

#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/asio/asio_policy.h"

#include "mdnspp/detail/native_socket.h"
#include "mdnspp/detail/native_sockaddr.h"
#include "mdnspp/detail/ipv6_interface_index.h"

#include <asio.hpp>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <cstddef>
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
    mdnspp::asio_socket socket{io, v6_options("2001:db8::dead"), ec};
    REQUIRE(ec == std::errc::invalid_argument);
    REQUIRE(socket.native_handle() == mdnspp::detail::invalid_socket);
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

TEST_CASE("asio_socket rejects every destination the native parser rejects", "[asio][socket][ipv6]")
{
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, v6_options("::1"), ec};
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
    mdnspp::asio_socket socket{io, v6_options("::1"), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("asio_socket construction on ::1 failed: " + ec.message());

    socket.send(mdnspp::endpoint{"::1", discard_port}, payload, ec);
    REQUIRE(ec != std::errc::invalid_argument);
}
#endif

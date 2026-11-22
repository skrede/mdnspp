#include "support/skip_or_fail.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/native_socket.h"

#include "mdnspp/default/default_timer.h"
#include "mdnspp/default/default_socket.h"
#include "mdnspp/default/default_context.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <system_error>

namespace {

uint16_t bound_port(mdnspp::detail::native_socket_t fd)
{
    sockaddr_storage addr{};
    socklen_t len = sizeof(addr);
    ::getsockname(fd, reinterpret_cast<sockaddr *>(&addr), &len);
    if(addr.ss_family == AF_INET6)
        return ntohs(reinterpret_cast<const sockaddr_in6 &>(addr).sin6_port);
    return ntohs(reinterpret_cast<const sockaddr_in &>(addr).sin_port);
}

std::optional<mdnspp::recv_metadata> receive_from_self(const char *group, const char *loopback)
{
    mdnspp::default_context ctx;
    std::error_code ec;
    std::optional<mdnspp::recv_metadata> received;
    bool expired = false;
    mdnspp::socket_options opts;
    opts.multicast_group = mdnspp::endpoint{group, 0};
    // Darwin rejects an IPv6 link-local group join with interface index 0 when it has no IPv6 route to the group.
    if(std::string_view{group}.find(':') != std::string_view::npos)
        opts.interface_address = loopback;
    mdnspp::default_socket socket(ctx, opts, ec);
    if(ec)
        mdnspp::test_support::skip_or_fail("default_socket construction failed: " + ec.message());
    socket.async_receive([&](std::error_code result, const mdnspp::recv_metadata &meta, std::span<std::byte>)
    {
        if(!result)
            received = meta;
    });
    mdnspp::default_timer deadline(ctx);
    deadline.expires_after(std::chrono::seconds{2});
    deadline.async_wait([&](std::error_code) { expired = true; });
    const std::array<std::byte, 4> payload{};
    socket.send(mdnspp::endpoint{loopback, bound_port(socket.native_handle())}, payload);
    while(!received && !expired)
        ctx.poll_one();
    return received;
}

}

TEST_CASE("a default_socket reports the TTL and interface of an IPv4 loopback datagram", "[native][recv_metadata]")
{
    const std::optional<mdnspp::recv_metadata> meta = receive_from_self("224.0.0.251", "127.0.0.1");

    REQUIRE(meta.has_value());
    REQUIRE(meta->ttl.has_value());
    REQUIRE(meta->recv_ifindex != 0);
}

TEST_CASE("a default_socket reports the hop limit and interface of an IPv6 loopback datagram",
          "[native][recv_metadata]")
{
    const std::optional<mdnspp::recv_metadata> meta = receive_from_self("ff02::fb", "::1");

    REQUIRE(meta.has_value());
    REQUIRE(meta->ttl.has_value());
    REQUIRE(meta->recv_ifindex != 0);
}

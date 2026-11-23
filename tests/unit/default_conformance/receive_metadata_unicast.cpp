#include "receive_helpers.h"

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <optional>

TEST_CASE("a default_socket reports the TTL and interface of an IPv4 loopback datagram", "[native][recv_metadata]")
{
    const std::optional<mdnspp::recv_metadata> meta =
        receive_from_self(loopback_options("224.0.0.251", "127.0.0.1"), "127.0.0.1");

    REQUIRE(meta.has_value());
    REQUIRE(meta->ttl.has_value());
    REQUIRE(meta->recv_ifindex == loopback_index());
    REQUIRE(meta->destination.has_value());
    REQUIRE(meta->destination == mdnspp::detail::parse_ip_address("127.0.0.1"));
    REQUIRE_FALSE(meta->destination->is_multicast());
}

TEST_CASE("a default_socket reports the hop limit and interface of an IPv6 loopback datagram",
          "[native][recv_metadata]")
{
    const std::optional<mdnspp::recv_metadata> meta = receive_from_self(loopback_options("ff02::fb", "::1"), "::1");

    REQUIRE(meta.has_value());
    REQUIRE(meta->ttl.has_value());
    REQUIRE(meta->recv_ifindex == loopback_index());
    REQUIRE(meta->destination.has_value());
    REQUIRE(meta->destination == mdnspp::detail::parse_ip_address("::1"));
    REQUIRE_FALSE(meta->destination->is_multicast());
}

TEST_CASE("a default_socket sends IPv4 unicast with TTL 255 by default", "[native][recv_metadata][ttl]")
{
    const std::optional<mdnspp::recv_metadata> meta =
        receive_from_self(loopback_options("224.0.0.251", "127.0.0.1"), "127.0.0.1");

    REQUIRE(meta.has_value());
    REQUIRE(ttl_of(meta) == 255);
}

TEST_CASE("a default_socket sends IPv6 unicast with hop limit 255 by default", "[native][recv_metadata][ttl]")
{
    const std::optional<mdnspp::recv_metadata> meta = receive_from_self(loopback_options("ff02::fb", "::1"), "::1");

    REQUIRE(meta.has_value());
    REQUIRE(ttl_of(meta) == 255);
}

TEST_CASE("a default_socket sends unicast with the configured multicast TTL", "[native][recv_metadata][ttl]")
{
    mdnspp::socket_options v4 = loopback_options("224.0.0.251", "127.0.0.1");
    mdnspp::socket_options v6 = loopback_options("ff02::fb", "::1");
    v4.multicast_ttl = 200;
    v6.multicast_ttl = 200;

    const std::optional<mdnspp::recv_metadata> meta_v4 = receive_from_self(v4, "127.0.0.1");
    const std::optional<mdnspp::recv_metadata> meta_v6 = receive_from_self(v6, "::1");

    REQUIRE(ttl_of(meta_v4) == 200);
    REQUIRE(ttl_of(meta_v6) == 200);
}

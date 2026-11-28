#include "helpers.h"

#include "default_conformance/receive_helpers.h"

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>

TEST_CASE("an asio_socket reports the TTL, interface and destination of an IPv4 loopback datagram",
          "[asio][recv_metadata]")
{
    const std::optional<mdnspp::recv_metadata> meta =
        asio_receive_from_self(loopback_options("224.0.0.251", "127.0.0.1"), "127.0.0.1");

    REQUIRE(meta.has_value());
    REQUIRE(ttl_of(meta) == 255);
    REQUIRE(meta->recv_ifindex == loopback_index());
    REQUIRE(meta->destination == mdnspp::detail::parse_ip_address("127.0.0.1"));
    REQUIRE_FALSE(meta->destination->is_multicast());
}

TEST_CASE("an asio_socket reports the hop limit, interface and destination of an IPv6 loopback datagram",
          "[asio][recv_metadata]")
{
    const std::optional<mdnspp::recv_metadata> meta =
        asio_receive_from_self(loopback_options("ff02::fb", "::1"), "::1");

    REQUIRE(meta.has_value());
    REQUIRE(ttl_of(meta) == 255);
    REQUIRE(meta->recv_ifindex == loopback_index());
    REQUIRE(meta->destination == mdnspp::detail::parse_ip_address("::1"));
    REQUIRE_FALSE(meta->destination->is_multicast());
}

TEST_CASE("an asio_socket sends unicast with the configured multicast TTL", "[asio][recv_metadata][ttl]")
{
    mdnspp::socket_options v4 = loopback_options("224.0.0.251", "127.0.0.1");
    mdnspp::socket_options v6 = loopback_options("ff02::fb", "::1");
    v4.multicast_ttl = 200;
    v6.multicast_ttl = 200;

    const std::optional<mdnspp::recv_metadata> meta_v4 = asio_receive_from_self(v4, "127.0.0.1");
    const std::optional<mdnspp::recv_metadata> meta_v6 = asio_receive_from_self(v6, "::1");

    REQUIRE(ttl_of(meta_v4) == 200);
    REQUIRE(ttl_of(meta_v6) == 200);
}

TEST_CASE("an asio_socket reports the group, interface and TTL of a looped IPv4 multicast datagram",
          "[asio][recv_metadata][multicast]")
{
    const uint32_t index = multicast_interface_index(false);
    const std::optional<mdnspp::recv_metadata> meta =
        asio_receive_from_self(interface_options("224.0.0.251", index), "224.0.0.251");

    REQUIRE(meta.has_value());
    REQUIRE(meta->destination == mdnspp::detail::parse_ip_address("224.0.0.251"));
    REQUIRE(meta->recv_ifindex == index);
    REQUIRE(meta->ttl.has_value());
}

TEST_CASE("an asio_socket reports the group, interface and hop limit of a looped IPv6 multicast datagram",
          "[asio][recv_metadata][multicast]")
{
    const uint32_t index = multicast_interface_index(true);
    const std::optional<mdnspp::recv_metadata> meta =
        asio_receive_from_self(interface_options("ff02::fb", index), "ff02::fb");

    REQUIRE(meta.has_value());
    REQUIRE(meta->destination == mdnspp::detail::parse_ip_address("ff02::fb"));
    REQUIRE(meta->recv_ifindex == index);
    REQUIRE(meta->ttl.has_value());
}

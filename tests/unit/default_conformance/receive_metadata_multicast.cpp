#include "receive_helpers.h"

#include "mdnspp/policy.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>

TEST_CASE("a default_socket reports the group, interface and TTL of a looped IPv4 multicast datagram",
          "[native][recv_metadata][multicast]")
{
    const uint32_t index = multicast_interface_index(false);
    const std::optional<mdnspp::recv_metadata> meta =
        receive_from_self(interface_options("224.0.0.251", index), "224.0.0.251");

    REQUIRE(meta.has_value());
    REQUIRE(meta->destination == mdnspp::detail::parse_ip_address("224.0.0.251"));
    REQUIRE(meta->recv_ifindex == index);
    REQUIRE(meta->ttl.has_value());
}

TEST_CASE("a default_socket reports the group, interface and hop limit of a looped IPv6 multicast datagram",
          "[native][recv_metadata][multicast]")
{
    const uint32_t index = multicast_interface_index(true);
    const std::optional<mdnspp::recv_metadata> meta =
        receive_from_self(interface_options("ff02::fb", index), "ff02::fb");

    REQUIRE(meta.has_value());
    REQUIRE(meta->destination == mdnspp::detail::parse_ip_address("ff02::fb"));
    REQUIRE(meta->recv_ifindex == index);
    REQUIRE(meta->ttl.has_value());
}

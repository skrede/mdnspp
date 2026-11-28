#include "netns/helpers.h"

#include "support/netns.h"
#include "support/ipv6_interface.h"

#include "mdnspp/socket_options.h"

#include "mdnspp/default/default_policy.h"

#include <catch2/catch_test_macros.hpp>

#include <unistd.h>

#include <arpa/inet.h>

#include <netinet/in.h>

#include <sys/socket.h>

#include <cstdint>
#include <system_error>

using mdnspp::test_support::netns_interface_index;
using mdnspp::test_support::require_netns_harness;

TEST_CASE("default_socket selects one of two interfaces sharing a link-local address by index", "[netns][ipv6]")
{
    require_netns_harness();
    mdnspp::socket_options opts = mdnspp::test_support::ipv6_group_options();
    opts.interface_index = netns_interface_index("l1");

    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket socket{ctx, opts, ec};
    REQUIRE_FALSE(ec);
    require_selected(socket, "l1");
}

TEST_CASE("default_socket selects one of two interfaces sharing a link-local address by name", "[netns][ipv6]")
{
    require_netns_harness();
    mdnspp::socket_options opts = mdnspp::test_support::ipv6_group_options();
    opts.interface_name = "l1";

    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket socket{ctx, opts, ec};
    REQUIRE_FALSE(ec);
    require_selected(socket, "l1");
}

TEST_CASE("default_socket selects one of two interfaces sharing a link-local address by scoped address",
          "[netns][ipv6]")
{
    require_netns_harness();
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket socket{ctx, mdnspp::test_support::ipv6_group_options("fe80::20%l1"), ec};
    REQUIRE_FALSE(ec);
    require_selected(socket, "l1");
}

TEST_CASE("netns harness opens sockets inside a peer namespace", "[netns]")
{
    require_netns_harness();
    sockaddr_in peer{};
    peer.sin_family = AF_INET;
    REQUIRE(::inet_pton(AF_INET, "10.20.1.2", &peer.sin_addr) == 1);
    const auto *addr = reinterpret_cast<const sockaddr *>(&peer);

    const int32_t in_p1 = mdnspp::test_support::open_udp_socket_in_netns("p1", AF_INET);
    CHECK(::bind(in_p1, addr, sizeof(peer)) == 0);
    ::close(in_p1);

    const int32_t here = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    REQUIRE(here >= 0);
    CHECK(::bind(here, addr, sizeof(peer)) != 0);
    ::close(here);
}

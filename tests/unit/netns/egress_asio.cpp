#include "netns/helpers.h"

#include "support/netns.h"
#include "support/ipv6_interface.h"

#include "mdnspp/asio/asio_policy.h"

#include <asio.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <system_error>

using mdnspp::test_support::netns_interface_index;
using mdnspp::test_support::require_netns_harness;

TEST_CASE("an unbound IPv6 asio_socket is pinned to the IPv4 egress interface", "[netns][egress][ipv6][asio]")
{
    require_netns_harness();
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, mdnspp::test_support::ipv6_group_options(), ec};
    REQUIRE_FALSE(ec);

    const uint32_t d1 = netns_interface_index("d1");
    CHECK(socket.interface_index() == d1);
    CHECK(mdnspp::test_support::ipv6_multicast_interface(socket.native_handle()) == d1);
    CHECK(joined_mdns_group("d1"));
    CHECK_FALSE(joined_mdns_group("d0"));
}

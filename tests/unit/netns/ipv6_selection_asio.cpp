#include "netns/helpers.h"

#include "support/netns.h"
#include "support/ipv6_interface.h"

#include "mdnspp/socket_options.h"

#include "mdnspp/asio/asio_policy.h"

#include <asio.hpp>

#include <catch2/catch_test_macros.hpp>

#include <system_error>

using mdnspp::test_support::netns_interface_index;
using mdnspp::test_support::require_netns_harness;

TEST_CASE("asio_socket selects one of two interfaces sharing a link-local address by index", "[netns][ipv6][asio]")
{
    require_netns_harness();
    mdnspp::socket_options opts = mdnspp::test_support::ipv6_group_options();
    opts.interface_index = netns_interface_index("l1");

    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, opts, ec};
    REQUIRE_FALSE(ec);
    require_selected(socket, "l1");
}

TEST_CASE("asio_socket selects one of two interfaces sharing a link-local address by name", "[netns][ipv6][asio]")
{
    require_netns_harness();
    mdnspp::socket_options opts = mdnspp::test_support::ipv6_group_options();
    opts.interface_name = "l1";

    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket socket{io, opts, ec};
    REQUIRE_FALSE(ec);
    require_selected(socket, "l1");
}

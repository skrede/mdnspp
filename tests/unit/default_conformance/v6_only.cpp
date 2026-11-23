#include "receive_helpers.h"

#include "support/skip_or_fail.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/default/default_socket.h"
#include "mdnspp/default/default_context.h"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>
#include <optional>
#include <system_error>

namespace {

void send_from_ipv4(const char *to, uint16_t port)
{
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket sender(ctx, loopback_options("224.0.0.251", "127.0.0.1"), ec);
    if(ec)
        mdnspp::test_support::skip_or_fail("IPv4 default_socket construction failed: " + ec.message());
    sender.send(mdnspp::endpoint{to, port}, probe_payload);
}

}

TEST_CASE("an IPv6 default_socket does not receive an IPv4 datagram sent to its port", "[native][ipv6][v6_only]")
{
    const std::optional<mdnspp::recv_metadata> meta = receive_with(loopback_options("ff02::fb", "::1"),
        [](mdnspp::default_socket &, uint16_t port) { send_from_ipv4("127.0.0.1", port); });

    INFO("received from " << (meta ? meta->sender.address : std::string{"nobody"}));
    REQUIRE_FALSE(meta.has_value());
}

TEST_CASE("an IPv6 default_socket receives an IPv6 datagram sent to its port", "[native][ipv6][v6_only]")
{
    const std::optional<mdnspp::recv_metadata> meta = receive_from_self(loopback_options("ff02::fb", "::1"), "::1");

    REQUIRE(meta.has_value());
    REQUIRE(meta->sender.address == "::1");
}

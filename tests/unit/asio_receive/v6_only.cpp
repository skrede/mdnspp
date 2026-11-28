#include "helpers.h"

#include "default_conformance/receive_helpers.h"

#include "support/skip_or_fail.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"

#include "mdnspp/asio/asio_socket.h"

#include <asio.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <cstdint>
#include <optional>
#include <system_error>

namespace {

void send_from_ipv4(const char *to, uint16_t port)
{
    asio::io_context io;
    std::error_code ec;
    mdnspp::asio_socket sender{io, loopback_options("224.0.0.251", "127.0.0.1"), ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("IPv4 asio_socket construction failed: " + ec.message());
    sender.send(mdnspp::endpoint{to, port}, probe_payload);
}

}

TEST_CASE("an IPv6 asio_socket does not receive an IPv4 datagram sent to its port", "[asio][ipv6][v6_only]")
{
    const std::optional<mdnspp::recv_metadata> meta = asio_receive_with(loopback_options("ff02::fb", "::1"),
        [](mdnspp::asio_socket &, uint16_t port) { send_from_ipv4("127.0.0.1", port); });

    INFO("received from " << (meta ? meta->sender.address : std::string{"nobody"}));
    REQUIRE_FALSE(meta.has_value());
}

TEST_CASE("an IPv6 asio_socket receives an IPv6 datagram sent to its port", "[asio][ipv6][v6_only]")
{
    const std::optional<mdnspp::recv_metadata> meta =
        asio_receive_from_self(loopback_options("ff02::fb", "::1"), "::1");

    REQUIRE(meta.has_value());
    REQUIRE(meta->sender.address == "::1");
}

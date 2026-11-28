#include "mdnspp/testing/mock_socket.h"
#include "mdnspp/testing/mock_executor.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <system_error>

using mdnspp::endpoint;
using mdnspp::recv_metadata;
using mdnspp::socket_options;
using mdnspp::testing::mock_socket;
using mdnspp::testing::mock_executor;
using mdnspp::detail::parse_ip_address;

namespace {

std::vector<std::byte> packet()
{
    return {std::byte{0x01}, std::byte{0x02}};
}

socket_options custom_group()
{
    socket_options opts;
    opts.multicast_group = endpoint{"ff02::fb", 5454};
    return opts;
}

std::optional<recv_metadata> receive_one(mock_socket &sock)
{
    std::optional<recv_metadata> received;
    sock.async_receive([&](std::error_code ec, const recv_metadata &meta, std::span<std::byte>)
    {
        if(!ec)
            received = meta;
    });
    return received;
}

recv_metadata unicast_metadata()
{
    return recv_metadata{.sender = endpoint{"192.0.2.7", 40000}, .ttl = uint8_t{64}, .recv_ifindex = 3,
                         .destination = parse_ip_address("192.0.2.1")};
}

void require_same(const recv_metadata &actual, const recv_metadata &expected)
{
    REQUIRE(actual.sender == expected.sender);
    REQUIRE(actual.ttl == expected.ttl);
    REQUIRE(actual.recv_ifindex == expected.recv_ifindex);
    REQUIRE(actual.destination == expected.destination);
}

}

TEST_CASE("the mock default metadata looks like multicast traffic on the default group", "[mock_socket][metadata]")
{
    mock_executor ex;
    const mock_socket sock{ex};
    const recv_metadata meta = sock.default_metadata();

    REQUIRE(meta.sender.address.empty());
    REQUIRE(meta.sender.port == 5353);
    REQUIRE(meta.destination == parse_ip_address("224.0.0.251"));
    REQUIRE(meta.ttl == uint8_t{255});
    REQUIRE(meta.recv_ifindex == 0);
}

TEST_CASE("the mock default metadata follows a custom group", "[mock_socket][metadata]")
{
    mock_executor ex;
    const mock_socket sock{ex, custom_group()};
    const recv_metadata meta = sock.default_metadata();

    REQUIRE(meta.sender.port == 5454);
    REQUIRE(meta.destination == parse_ip_address("ff02::fb"));
    REQUIRE(meta.ttl == uint8_t{255});
    REQUIRE(meta.recv_ifindex == 0);
}

TEST_CASE("a mock packet enqueued without metadata carries the default metadata", "[mock_socket][metadata]")
{
    mock_executor ex;
    mock_socket sock{ex, custom_group()};
    sock.enqueue(packet());

    const std::optional<recv_metadata> meta = receive_one(sock);

    REQUIRE(meta.has_value());
    require_same(*meta, sock.default_metadata());
}

TEST_CASE("a mock packet enqueued with a sender keeps the other defaults", "[mock_socket][metadata]")
{
    mock_executor ex;
    mock_socket sock{ex};
    sock.enqueue(packet(), endpoint{"192.0.2.9", 5353});

    const std::optional<recv_metadata> meta = receive_one(sock);

    REQUIRE(meta.has_value());
    REQUIRE(meta->sender == endpoint{"192.0.2.9", 5353});
    REQUIRE(meta->destination == sock.default_metadata().destination);
    REQUIRE(meta->ttl == uint8_t{255});
}

TEST_CASE("explicit mock metadata passes through enqueue unchanged", "[mock_socket][metadata]")
{
    mock_executor ex;
    mock_socket sock{ex};
    sock.enqueue(packet(), unicast_metadata());

    const std::optional<recv_metadata> meta = receive_one(sock);

    REQUIRE(meta.has_value());
    require_same(*meta, unicast_metadata());
}

TEST_CASE("explicit mock metadata passes through inject_receive unchanged", "[mock_socket][metadata]")
{
    mock_executor ex;
    mock_socket sock{ex};
    std::optional<recv_metadata> received;
    sock.async_receive([&](std::error_code, const recv_metadata &meta, std::span<std::byte>) { received = meta; });

    sock.inject_receive(unicast_metadata(), packet());

    REQUIRE(received.has_value());
    require_same(*received, unicast_metadata());
}

TEST_CASE("explicit mock metadata injected without a pending receive is queued unchanged", "[mock_socket][metadata]")
{
    mock_executor ex;
    mock_socket sock{ex};
    sock.inject_receive(unicast_metadata(), packet());

    const std::optional<recv_metadata> meta = receive_one(sock);

    REQUIRE(meta.has_value());
    require_same(*meta, unicast_metadata());
}

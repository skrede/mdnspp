#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/ip_address.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <cstddef>
#include <optional>
#include <system_error>

using mdnspp::endpoint;
using mdnspp::recv_metadata;
using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_socket;
using mdnspp::inproc::inproc_executor;
using mdnspp::inproc::inproc_socket_options;
using mdnspp::detail::parse_ip_address;

namespace {

const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}};

inproc_socket_options group_options(const endpoint &group)
{
    inproc_socket_options opts;
    opts.multicast_group = group;
    return opts;
}

std::optional<recv_metadata> receive_one(inproc_bus<> &bus, inproc_socket<> &receiver)
{
    std::optional<recv_metadata> received;
    receiver.async_receive([&](std::error_code ec, const recv_metadata &meta, std::span<std::byte>)
    {
        if(!ec)
            received = meta;
    });
    while(bus.deliver_one())
    {
    }
    return received;
}

std::optional<recv_metadata> multicast_to(const endpoint &group)
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    inproc_socket<> sender{ex, group_options(group)};
    inproc_socket<> receiver{ex, group_options(group)};
    sender.send(group, std::span<const std::byte>{payload});
    return receive_one(bus, receiver);
}

}

TEST_CASE("an in-process multicast delivery reports the IPv4 group as its destination", "[inproc][destination]")
{
    const std::optional<recv_metadata> meta = multicast_to(endpoint{"224.0.0.251", 5353});

    REQUIRE(meta.has_value());
    REQUIRE(meta->destination == parse_ip_address("224.0.0.251"));
    REQUIRE(meta->destination->is_multicast());
}

TEST_CASE("an in-process multicast delivery reports the IPv6 group as its destination", "[inproc][destination]")
{
    const std::optional<recv_metadata> meta = multicast_to(endpoint{"ff02::fb", 5353});

    REQUIRE(meta.has_value());
    REQUIRE(meta->destination == parse_ip_address("ff02::fb"));
    REQUIRE(meta->destination->is_multicast());
}

TEST_CASE("an in-process unicast delivery reports the receiving socket's address as its destination",
          "[inproc][destination]")
{
    inproc_bus<> bus;
    inproc_executor<> ex{bus};
    inproc_socket<> sender{ex};
    inproc_socket<> receiver{ex};
    sender.send(receiver.assigned_endpoint(), std::span<const std::byte>{payload});

    const std::optional<recv_metadata> meta = receive_one(bus, receiver);

    REQUIRE(meta.has_value());
    REQUIRE(meta->destination == parse_ip_address(receiver.assigned_endpoint().address));
    REQUIRE(meta->destination != parse_ip_address(sender.assigned_endpoint().address));
    REQUIRE_FALSE(meta->destination->is_multicast());
}

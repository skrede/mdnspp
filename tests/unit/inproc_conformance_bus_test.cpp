#include "mdnspp/inproc/inproc_bus.h"
#include "mdnspp/inproc/inproc_timer.h"
#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_executor.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/socket_options.h"

#include "mdnspp/testing/test_clock.h"

#include <catch2/catch_test_macros.hpp>

#include <span>
#include <vector>
#include <cstddef>
#include <system_error>

using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_executor;
using mdnspp::inproc::inproc_socket;
using mdnspp::testing::test_clock;
using Clock = test_clock;

namespace {

struct receipt
{
    bool received;
    mdnspp::endpoint sender;
    std::vector<std::byte> data;
};

void record_into(inproc_socket<Clock> &sock, receipt &r)
{
    sock.async_receive([&r](std::error_code, const mdnspp::recv_metadata &meta, std::span<std::byte> data)
    {
        r.sender = meta.sender;
        r.data.assign(data.begin(), data.end());
        r.received = true;
    });
}

}

TEST_CASE("inproc_bus multicast delivery", "[inproc][bus]")
{
    test_clock::reset();
    inproc_bus<Clock> bus;
    inproc_executor<Clock> ex{bus};

    mdnspp::inproc::inproc_socket_options opts{};
    inproc_socket<Clock> sock_a{ex, opts};
    inproc_socket<Clock> sock_b{ex, opts};

    receipt b{};
    receipt a{};
    record_into(sock_b, b);
    record_into(sock_a, a);

    const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    sock_a.send(opts.multicast_group, std::span<const std::byte>{payload});

    ex.drain();

    REQUIRE(b.received);
    REQUIRE(b.data.size() == 3);
    REQUIRE(b.data[0] == std::byte{0x01});
    // Loopback is enabled by default, so the sender also receives its own packet.
    REQUIRE(a.received);
}

TEST_CASE("inproc_bus unicast delivery", "[inproc][bus]")
{
    test_clock::reset();
    inproc_bus<Clock> bus;
    inproc_executor<Clock> ex{bus};

    inproc_socket<Clock> sock_a{ex};
    inproc_socket<Clock> sock_b{ex};

    receipt b{};
    receipt a{};
    record_into(sock_b, b);
    record_into(sock_a, a);

    const std::byte payload[] = {std::byte{0xAB}};
    sock_a.send(sock_b.assigned_endpoint(), std::span<const std::byte>{payload});

    ex.drain();

    REQUIRE(b.received);
    REQUIRE_FALSE(a.received);
}

TEST_CASE("inproc_bus loopback disabled", "[inproc][bus]")
{
    test_clock::reset();
    inproc_bus<Clock> bus;
    inproc_executor<Clock> ex{bus};

    mdnspp::inproc::inproc_socket_options opts_no_loopback{};
    opts_no_loopback.multicast_loopback = mdnspp::loopback_mode::disabled;
    inproc_socket<Clock> sender{ex, opts_no_loopback};

    mdnspp::inproc::inproc_socket_options opts_loopback{};
    inproc_socket<Clock> receiver{ex, opts_loopback};

    receipt at_sender{};
    receipt at_receiver{};
    record_into(sender, at_sender);
    record_into(receiver, at_receiver);

    const std::byte payload[] = {std::byte{0x42}};
    sender.send(opts_no_loopback.multicast_group, std::span<const std::byte>{payload});

    ex.drain();

    REQUIRE_FALSE(at_sender.received);
    REQUIRE(at_receiver.received);
}

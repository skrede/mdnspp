// tests/local_conformance_test.cpp

#include "mdnspp/policy.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/testing/test_clock.h"

#include "mdnspp/local/local_bus.h"
#include "mdnspp/local/local_timer.h"
#include "mdnspp/local/local_socket.h"
#include "mdnspp/local/local_policy.h"
#include "mdnspp/local/local_executor.h"

#include <catch2/catch_test_macros.hpp>

using mdnspp::local::local_bus;
using mdnspp::local::local_executor;
using mdnspp::local::local_socket;
using mdnspp::local::local_timer;
using mdnspp::testing::test_clock;
using Clock = test_clock;

static_assert(mdnspp::Policy<mdnspp::LocalTestPolicy>,
    "local_policy<test_clock> must satisfy Policy concept");
static_assert(mdnspp::SocketLike<mdnspp::local::local_socket<test_clock>>,
    "local_socket<test_clock> must satisfy SocketLike concept");
static_assert(mdnspp::TimerLike<mdnspp::local::local_timer<test_clock>>,
    "local_timer<test_clock> must satisfy TimerLike concept");

TEST_CASE("local_policy satisfies Policy concept", "[local][conformance]")
{
    test_clock::reset();
    local_bus<Clock> bus;
    local_executor<Clock> ex{bus};

    local_socket<Clock> sock{ex};
    local_timer<Clock> timer{ex};

    // Just verify construction and basic wiring — no crash
    REQUIRE_FALSE(bus.has_pending_packets());
    REQUIRE_FALSE(timer.has_pending());
}

TEST_CASE("local_bus multicast delivery", "[local][bus]")
{
    test_clock::reset();
    local_bus<Clock> bus;
    local_executor<Clock> ex{bus};

    mdnspp::socket_options opts{};
    local_socket<Clock> sock_a{ex, opts};
    local_socket<Clock> sock_b{ex, opts};

    std::vector<std::byte> received_by_b;
    mdnspp::endpoint sender_b;
    bool b_received = false;

    sock_b.async_receive([&](const mdnspp::recv_metadata &meta, std::span<std::byte> data)
    {
        sender_b = meta.sender;
        received_by_b.assign(data.begin(), data.end());
        b_received = true;
    });

    std::vector<std::byte> received_by_a;
    bool a_received = false;
    sock_a.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte> data)
    {
        received_by_a.assign(data.begin(), data.end());
        a_received = true;
    });

    const std::byte payload[] = {std::byte{0x01}, std::byte{0x02}, std::byte{0x03}};
    sock_a.send(opts.multicast_group, std::span<const std::byte>{payload});

    ex.drain();

    REQUIRE(b_received);
    REQUIRE(received_by_b.size() == 3);
    REQUIRE(received_by_b[0] == std::byte{0x01});
    // Loopback enabled by default — sender also receives its own packet
    REQUIRE(a_received);
}

TEST_CASE("local_bus unicast delivery", "[local][bus]")
{
    test_clock::reset();
    local_bus<Clock> bus;
    local_executor<Clock> ex{bus};

    local_socket<Clock> sock_a{ex};
    local_socket<Clock> sock_b{ex};

    bool b_received = false;
    bool a_received = false;

    sock_b.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        b_received = true;
    });

    sock_a.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        a_received = true;
    });

    const std::byte payload[] = {std::byte{0xAB}};
    // Send unicast to B's assigned endpoint
    sock_a.send(sock_b.assigned_endpoint(), std::span<const std::byte>{payload});

    ex.drain();

    REQUIRE(b_received);
    REQUIRE_FALSE(a_received);
}

TEST_CASE("local_bus loopback disabled", "[local][bus]")
{
    test_clock::reset();
    local_bus<Clock> bus;
    local_executor<Clock> ex{bus};

    mdnspp::socket_options opts_no_loopback{};
    opts_no_loopback.multicast_loopback = mdnspp::loopback_mode::disabled;

    local_socket<Clock> sender{ex, opts_no_loopback};

    mdnspp::socket_options opts_loopback{};
    local_socket<Clock> receiver{ex, opts_loopback};

    bool sender_received = false;
    bool receiver_received = false;

    sender.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        sender_received = true;
    });

    receiver.async_receive([&](const mdnspp::recv_metadata &, std::span<std::byte>)
    {
        receiver_received = true;
    });

    const std::byte payload[] = {std::byte{0x42}};
    sender.send(opts_no_loopback.multicast_group, std::span<const std::byte>{payload});

    ex.drain();

    REQUIRE_FALSE(sender_received);
    REQUIRE(receiver_received);
}

TEST_CASE("local_timer fires on clock advance", "[local][timer]")
{
    test_clock::reset();
    local_bus<Clock> bus;
    local_executor<Clock> ex{bus};

    local_timer<Clock> timer{ex};

    std::error_code received_ec = std::make_error_code(std::errc::interrupted);
    bool fired = false;

    timer.expires_after(std::chrono::milliseconds{100});
    timer.async_wait([&](std::error_code ec)
    {
        received_ec = ec;
        fired = true;
    });

    REQUIRE(timer.has_pending());

    // Advance clock but not enough — timer should not fire
    test_clock::advance(std::chrono::milliseconds{50});
    ex.drain();
    REQUIRE_FALSE(fired);

    // Advance clock past expiry
    test_clock::advance(std::chrono::milliseconds{50});
    ex.drain();

    REQUIRE(fired);
    REQUIRE_FALSE(received_ec);
}

TEST_CASE("local_timer cancel", "[local][timer]")
{
    test_clock::reset();
    local_bus<Clock> bus;
    local_executor<Clock> ex{bus};

    local_timer<Clock> timer{ex};

    std::error_code received_ec{};
    bool fired = false;

    timer.expires_after(std::chrono::milliseconds{1000});
    timer.async_wait([&](std::error_code ec)
    {
        received_ec = ec;
        fired = true;
    });

    REQUIRE(timer.has_pending());

    timer.cancel();

    REQUIRE_FALSE(timer.has_pending());
    REQUIRE(fired);
    REQUIRE(received_ec == std::make_error_code(std::errc::operation_canceled));
}

TEST_CASE("local_executor post and drain", "[local][executor]")
{
    test_clock::reset();
    local_bus<Clock> bus;
    local_executor<Clock> ex{bus};

    std::vector<int> order;

    mdnspp::LocalTestPolicy::post(ex, [&] { order.push_back(1); });
    mdnspp::LocalTestPolicy::post(ex, [&] { order.push_back(2); });
    mdnspp::LocalTestPolicy::post(ex, [&] { order.push_back(3); });

    REQUIRE(order.empty());

    ex.drain();

    REQUIRE(order == std::vector<int>{1, 2, 3});
}

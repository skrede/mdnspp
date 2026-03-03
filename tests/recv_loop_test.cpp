#include "mdnspp/recv_loop.h"
#include "mdnspp/testing/mock_socket_policy.h"
#include "mdnspp/testing/mock_timer_policy.h"

#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <cstddef>
#include <span>
#include <vector>

using namespace mdnspp;
using namespace mdnspp::testing;

static constexpr std::chrono::milliseconds SILENCE_TIMEOUT{500};

// Helper: build a packet of N bytes (value = i % 256)
static std::vector<std::byte> make_packet(std::size_t n)
{
    std::vector<std::byte> v(n);
    for(std::size_t i = 0; i < n; ++i)
        v[i] = static_cast<std::byte>(i % 256);
    return v;
}

TEST_CASE("recv_loop delivers injected packets")
{
    MockSocketPolicy sock;
    MockTimerPolicy timer;
    auto pkt = make_packet(8);
    sock.enqueue(pkt);

    std::vector<std::vector<std::byte>> received;
    recv_loop loop{
        std::move(sock),
        std::move(timer),
        SILENCE_TIMEOUT,
        [&](std::span<std::byte> data, endpoint /*ep*/)
        {
            received.emplace_back(data.begin(), data.end());
        },
        [] {}};

    loop.start();

    REQUIRE(received.size() == 1);
    REQUIRE(received[0] == pkt);
}

TEST_CASE("recv_loop silence callback fires on timer fire")
{
    MockSocketPolicy sock;
    MockTimerPolicy timer;

    bool silence_called = false;
    recv_loop loop{
        std::move(sock),
        std::move(timer),
        SILENCE_TIMEOUT,
        [](std::span<std::byte>, endpoint) {},
        [&] { silence_called = true; }};

    loop.start();

    // Fire the pending timer handler — simulates silence timeout expiring
    loop.timer().fire();

    REQUIRE(silence_called == true);
}

TEST_CASE("recv_loop stop is idempotent")
{
    MockSocketPolicy sock;
    MockTimerPolicy timer;

    recv_loop loop{
        std::move(sock),
        std::move(timer),
        SILENCE_TIMEOUT,
        [](std::span<std::byte>, endpoint) {},
        [] {}};

    loop.start();

    // Calling stop() twice must not crash or double-invoke cancel
    REQUIRE_NOTHROW(loop.stop());
    REQUIRE_NOTHROW(loop.stop());
}

TEST_CASE("recv_loop stop prevents on_packet after stop")
{
    MockSocketPolicy sock;
    MockTimerPolicy timer;

    // Enqueue a packet — but stop() before start()
    sock.enqueue(make_packet(4));

    int packet_calls = 0;
    recv_loop loop{
        std::move(sock),
        std::move(timer),
        SILENCE_TIMEOUT,
        [&](std::span<std::byte>, endpoint) { ++packet_calls; },
        [] {}};

    loop.stop();
    loop.start(); // arm_receive() checks m_stopped first — should be a no-op

    REQUIRE(packet_calls == 0);
}

TEST_CASE("recv_loop resets silence timer on each packet")
{
    MockSocketPolicy sock;
    MockTimerPolicy timer;

    // Enqueue 2 packets — each delivery should call arm_silence_timer()
    sock.enqueue(make_packet(4));
    sock.enqueue(make_packet(4));

    recv_loop loop{
        std::move(sock),
        std::move(timer),
        SILENCE_TIMEOUT,
        [](std::span<std::byte>, endpoint) {},
        [] {}};

    loop.start();

    // start() calls arm_silence_timer() once, then:
    //   packet 1 triggers arm_silence_timer() (expires_after +1) + arm_receive()
    //   packet 2 triggers arm_silence_timer() (expires_after +1) + arm_receive() (no-op)
    // Minimum cancel_count >= 2 (at least 2 expires_after calls post-initial)
    REQUIRE(loop.timer().cancel_count() >= 2);
}

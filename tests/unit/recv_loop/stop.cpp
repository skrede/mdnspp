#include "recv_loop/helpers.h"

#include <catch2/generators/catch_generators.hpp>

#include <optional>

using namespace mdnspp::test_support;

TEST_CASE("recv_loop stop is idempotent")
{
    loop_rig rig;
    rig.loop.start();
    REQUIRE_NOTHROW(rig.loop.stop());
    REQUIRE_NOTHROW(rig.loop.stop());
}

TEST_CASE("recv_loop stop prevents on_packet after stop")
{
    loop_rig rig;
    rig.sock.enqueue(make_packet(4));
    rig.loop.stop();
    rig.loop.start();
    REQUIRE(rig.packets.empty());
}

TEST_CASE("recv_loop leaves no receive armed after stop")
{
    loop_rig rig;
    rig.loop.start();
    expect_armed(rig);
    rig.loop.stop();
    REQUIRE_FALSE(rig.sock.has_pending_receive());
}

namespace {

struct reentrant_rig
{
    mdnspp::testing::mock_executor ex;
    mdnspp::testing::mock_socket sock;
    mdnspp::testing::mock_timer timer;
    bool relevant;
    std::optional<mdnspp::detail::recv_loop<mdnspp::testing::mock_policy>> loop;

    explicit reentrant_rig(bool packet_relevant)
        : ex{}
        , sock{ex}
        , timer{ex}
        , relevant{packet_relevant}
        , loop{}
    {
        loop.emplace(sock, timer, SILENCE_TIMEOUT,
                     [this](const mdnspp::recv_metadata &, std::span<std::byte>) -> bool
                     {
                         loop->stop();
                         return relevant;
                     },
                     [this] { loop->stop(); }, [this](std::error_code) { loop->stop(); });
        loop->start();
    }

    void expect_idle() const
    {
        REQUIRE_FALSE(timer.has_pending());
        REQUIRE_FALSE(sock.has_pending_receive());
    }
};

}

TEST_CASE("recv_loop arms nothing after a packet callback stops it")
{
    const bool relevant = GENERATE(true, false);
    reentrant_rig rig(relevant);
    rig.sock.inject_receive(mdnspp::endpoint{}, make_packet(4));
    rig.expect_idle();
}

TEST_CASE("recv_loop arms nothing after the silence callback stops it")
{
    reentrant_rig rig(true);
    rig.timer.fire();
    rig.expect_idle();
}

TEST_CASE("recv_loop arms nothing after the error callback stops it")
{
    reentrant_rig rig(true);
    rig.sock.inject_error(std::make_error_code(std::errc::bad_file_descriptor));
    rig.expect_idle();
}

TEST_CASE("recv_loop start after stop arms nothing")
{
    loop_rig rig;
    rig.loop.stop();
    rig.loop.start();
    REQUIRE_FALSE(rig.timer.has_pending());
    REQUIRE_FALSE(rig.sock.has_pending_receive());
}

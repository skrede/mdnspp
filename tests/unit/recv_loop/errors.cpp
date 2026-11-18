#include "recv_loop/helpers.h"

using namespace mdnspp;
using namespace mdnspp::test_support;
using namespace std::chrono_literals;

TEST_CASE("recv_loop re-arms the receive after a transient error")
{
    loop_rig rig;
    rig.loop.start();
    expect_armed(rig);
    fail_transiently(rig, std::errc::connection_reset);
    REQUIRE(rig.errors.empty());
    expect_armed(rig);
    rig.sock.inject_receive(endpoint{}, make_packet(4));
    REQUIRE(rig.packets.size() == 1);
}

TEST_CASE("recv_loop backs off on consecutive transient errors and resets on success")
{
    loop_rig rig;
    rig.loop.start();
    expect_armed(rig);
    fail_transiently(rig, std::errc::not_enough_memory);
    expect_armed(rig);
    REQUIRE(rig.timer.last_duration() == SILENCE_TIMEOUT);
    fail_transiently(rig, std::errc::not_enough_memory);
    expect_backoff(rig, 10ms);
    rig.timer.fire();
    expect_armed(rig);
    REQUIRE(rig.timer.last_duration() <= SILENCE_TIMEOUT);
    fail_transiently(rig, std::errc::no_buffer_space);
    expect_backoff(rig, 20ms);
    rig.timer.fire();
    expect_armed(rig);
    rig.sock.inject_receive(endpoint{}, make_packet(4));
    REQUIRE(rig.packets.size() == 1);
    expect_armed(rig);
    fail_transiently(rig, std::errc::not_enough_memory);
    expect_armed(rig);
    REQUIRE(rig.errors.empty());
}

TEST_CASE("recv_loop backoff caps at 500 ms under persistent transient failure")
{
    loop_rig rig;
    rig.loop.start();
    fail_transiently(rig, std::errc::no_buffer_space);
    std::chrono::milliseconds last{0};
    for(int i = 0; i < 12; ++i)
    {
        fail_transiently(rig, std::errc::no_buffer_space);
        REQUIRE_FALSE(rig.sock.has_pending_receive());
        last = rig.timer.last_duration();
        REQUIRE(last <= 500ms);
        rig.timer.fire();
        expect_armed(rig);
    }
    REQUIRE(last == 500ms);
}

TEST_CASE("recv_loop reports a fatal error and stops re-arming")
{
    loop_rig rig;
    rig.loop.start();
    expect_armed(rig);
    fail_transiently(rig, std::errc::operation_canceled);
    REQUIRE(rig.errors.size() == 1);
    REQUIRE(rig.errors[0] == std::make_error_code(std::errc::operation_canceled));
    REQUIRE_FALSE(rig.sock.has_pending_receive());
    REQUIRE(rig.packets.empty());
}

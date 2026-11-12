#include "recv_loop/helpers.h"

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

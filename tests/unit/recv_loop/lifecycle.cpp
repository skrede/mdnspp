#include "recv_loop/helpers.h"

using namespace mdnspp::test_support;

TEST_CASE("recv_loop delivers injected packets")
{
    loop_rig rig;
    auto pkt = make_packet(8);
    rig.sock.enqueue(pkt);
    rig.loop.start();
    REQUIRE(rig.packets.size() == 1);
    REQUIRE(rig.packets[0] == pkt);
}

TEST_CASE("recv_loop silence callback fires on timer fire")
{
    loop_rig rig;
    rig.loop.start();
    rig.timer.fire();
    REQUIRE(rig.silences == 1);
}

TEST_CASE("recv_loop resets silence timer on each packet")
{
    loop_rig rig;
    rig.sock.enqueue(make_packet(4));
    rig.sock.enqueue(make_packet(4));
    rig.loop.start();
    REQUIRE(rig.timer.cancel_count() >= 2);
}

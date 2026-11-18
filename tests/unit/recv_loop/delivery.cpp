#include "recv_loop/helpers.h"

#include <optional>

using namespace mdnspp;
using namespace mdnspp::test_support;

TEST_CASE("recv_loop with ttl_unknown_policy::accept passes nullopt TTL packets")
{
    loop_rig rig{255, ttl_unknown_policy::accept};
    rig.sock.enqueue(make_packet(8), endpoint{}, std::optional<uint8_t>{});
    rig.loop.start();
    REQUIRE(rig.packets.size() == 1);
}

TEST_CASE("recv_loop with ttl_unknown_policy::reject drops nullopt TTL packets")
{
    loop_rig rig{255, ttl_unknown_policy::reject};
    rig.sock.enqueue(make_packet(8), endpoint{}, std::optional<uint8_t>{});
    rig.loop.start();
    REQUIRE(rig.packets.empty());
}

TEST_CASE("recv_loop drops populated TTL below receive_ttl_minimum")
{
    loop_rig rig{255, ttl_unknown_policy::accept};
    rig.sock.enqueue(make_packet(8), endpoint{}, std::optional<uint8_t>{uint8_t{10}});
    rig.loop.start();
    REQUIRE(rig.packets.empty());
}

TEST_CASE("recv_loop passes populated TTL at or above receive_ttl_minimum")
{
    loop_rig rig{255, ttl_unknown_policy::accept};
    rig.sock.enqueue(make_packet(8), endpoint{}, std::optional<uint8_t>{uint8_t{255}});
    rig.loop.start();
    REQUIRE(rig.packets.size() == 1);
}

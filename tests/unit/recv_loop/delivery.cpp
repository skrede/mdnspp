#include "recv_loop/helpers.h"

#include "mdnspp/policy.h"

#include <cstdint>
#include <optional>

using namespace mdnspp;
using namespace mdnspp::test_support;

namespace {

recv_metadata with_ttl(const testing::mock_socket &sock, std::optional<uint8_t> ttl)
{
    recv_metadata meta = sock.default_metadata();
    meta.ttl = ttl;
    return meta;
}

}

TEST_CASE("recv_loop with ttl_unknown_policy::accept passes nullopt TTL packets")
{
    loop_rig rig{255, ttl_unknown_policy::accept};
    rig.sock.enqueue(make_packet(8), with_ttl(rig.sock, std::nullopt));
    rig.loop.start();
    REQUIRE(rig.packets.size() == 1);
}

TEST_CASE("recv_loop with ttl_unknown_policy::reject drops nullopt TTL packets")
{
    loop_rig rig{255, ttl_unknown_policy::reject};
    rig.sock.enqueue(make_packet(8), with_ttl(rig.sock, std::nullopt));
    rig.loop.start();
    REQUIRE(rig.packets.empty());
}

TEST_CASE("recv_loop drops populated TTL below receive_ttl_minimum")
{
    loop_rig rig{255, ttl_unknown_policy::accept};
    rig.sock.enqueue(make_packet(8), with_ttl(rig.sock, uint8_t{10}));
    rig.loop.start();
    REQUIRE(rig.packets.empty());
}

TEST_CASE("recv_loop passes populated TTL at or above receive_ttl_minimum")
{
    loop_rig rig{255, ttl_unknown_policy::accept};
    rig.sock.enqueue(make_packet(8), with_ttl(rig.sock, uint8_t{255}));
    rig.loop.start();
    REQUIRE(rig.packets.size() == 1);
}

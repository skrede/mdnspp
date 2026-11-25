#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <algorithm>

namespace {

bool answered(server_rig &rig, std::optional<ip_address> destination, const endpoint &querier, uint32_t ifindex)
{
    feed(rig, service_query(), arriving(rig.peer.socket(), querier, destination, ifindex));
    return std::ranges::any_of(rig.peer.socket().sent_packets(), [&querier](const sent_packet &p)
    {
        return p.dest == querier;
    });
}

}

TEST_CASE("a server ignores a direct unicast query from an off-link source", "[gate][on-link][server]")
{
    const uint32_t loopback = index_of_127_0_0_1();
    server_rig rig;
    CHECK_FALSE(answered(rig, address_of("127.0.0.1"), endpoint{"203.0.113.9", 40000}, loopback));
}

TEST_CASE("a server answers a direct unicast query from a source on the receiving interface's subnet",
          "[gate][on-link][server]")
{
    const uint32_t loopback = index_of_127_0_0_1();
    server_rig rig;
    CHECK(answered(rig, address_of("127.0.0.1"), endpoint{"127.0.0.2", 40000}, loopback));
}

TEST_CASE("a server answers an off-link query whose destination is unknown", "[gate][on-link][server]")
{
    const uint32_t loopback = index_of_127_0_0_1();
    server_rig rig;
    CHECK(answered(rig, std::nullopt, endpoint{"203.0.113.9", 40000}, loopback));
}

TEST_CASE("a server answers a multicast query from an off-link source", "[gate][on-link][server]")
{
    const uint32_t loopback = index_of_127_0_0_1();
    server_rig rig;
    CHECK(answered(rig, address_of("224.0.0.251"), endpoint{"203.0.113.9", 40000}, loopback));
}

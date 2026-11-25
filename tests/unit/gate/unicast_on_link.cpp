#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

TEST_CASE("a querier does not report a unicast response from an off-link source", "[gate][on-link][querier]")
{
    const uint32_t loopback = index_of_127_0_0_1();
    querier_rig rig{response_mode::unicast};
    const recv_metadata off_link =
        arriving(rig.peer.socket(), endpoint{"203.0.113.9", mdns_port}, address_of("127.0.0.1"), loopback);
    feed(rig, service_response("Offlink"), off_link);

    CHECK(rig.reported("Offlink") == 0);
}

TEST_CASE("a querier reports a unicast response from a source on the receiving interface's subnet",
          "[gate][on-link][querier]")
{
    const uint32_t loopback = index_of_127_0_0_1();
    querier_rig rig{response_mode::unicast};
    const recv_metadata on_link =
        arriving(rig.peer.socket(), endpoint{"127.0.0.2", mdns_port}, address_of("127.0.0.1"), loopback);
    feed(rig, service_response("Onlink"), on_link);

    CHECK(rig.reported("Onlink") == 1);
}

TEST_CASE("a querier reports a multicast response from an off-link source", "[gate][on-link][querier]")
{
    const uint32_t loopback = index_of_127_0_0_1();
    querier_rig rig{response_mode::unicast};
    const recv_metadata multicast =
        arriving(rig.peer.socket(), endpoint{"203.0.113.9", mdns_port}, address_of("224.0.0.251"), loopback);
    feed(rig, service_response("Multicast"), multicast);

    CHECK(rig.reported("Multicast") == 1);
}

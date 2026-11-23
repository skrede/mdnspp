#include "netns/bound_peers.h"

#include "support/netns.h"

#include <catch2/catch_test_macros.hpp>

#include <string>

using mdnspp::test_support::require_netns_harness;

namespace {

void send_announcement(const std::string &netns, const std::string &device, const std::string &source,
                       const std::string &group)
{
    const int32_t fd =
        mdnspp::test_support::open_multicast_sender_in_netns(netns, device, mdnspp::endpoint{source, mdns_port});
    announce_and_close(fd, group);
}

}

TEST_CASE("a peer bound to an interface ignores IPv4 multicast that arrived on another interface",
          "[netns][attribution]")
{
    require_netns_harness();
    bound_observers peers{"224.0.0.251"};
    send_announcement("p1", "q1", "10.20.1.2", "224.0.0.251");
    peers.settle();

    CHECK(peers.on_d0.records_from("10.20.1.2") == 0);
    CHECK(peers.on_d1.records_from("10.20.1.2") > 0);
}

TEST_CASE("a peer bound to an interface receives IPv4 multicast from that interface", "[netns][attribution]")
{
    require_netns_harness();
    bound_observers peers{"224.0.0.251"};
    send_announcement("p0", "q0", "10.20.0.2", "224.0.0.251");
    peers.settle();

    CHECK(peers.on_d0.records_from("10.20.0.2") > 0);
    CHECK(peers.on_d1.records_from("10.20.0.2") == 0);
}

TEST_CASE("a peer bound to an interface ignores IPv6 multicast that arrived on another interface",
          "[netns][attribution]")
{
    require_netns_harness();
    bound_observers peers{"ff02::fb"};
    send_announcement("p1", "q1", "fd20:1::2", "ff02::fb");
    peers.settle();

    CHECK(peers.on_d0.records_from("fd20:1::2") == 0);
    CHECK(peers.on_d1.records_from("fd20:1::2") > 0);
}

TEST_CASE("a peer bound to an interface receives IPv6 multicast from that interface", "[netns][attribution]")
{
    require_netns_harness();
    bound_observers peers{"ff02::fb"};
    send_announcement("p0", "q0", "fd20::2", "ff02::fb");
    peers.settle();

    CHECK(peers.on_d0.records_from("fd20::2") > 0);
    CHECK(peers.on_d1.records_from("fd20::2") == 0);
}

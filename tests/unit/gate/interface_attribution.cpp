#include "helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>

namespace {

constexpr uint32_t bound = 2;

socket_options bound_options(std::optional<uint32_t> index = bound)
{
    return socket_options{.interface_index = index};
}

recv_metadata arriving_on(const mock_socket &socket, const char *destination, uint32_t recv_ifindex)
{
    return arriving(socket, endpoint{"127.0.0.1", mdns_port},
                    destination != nullptr ? std::optional{address_of(destination)} : std::nullopt, recv_ifindex);
}

std::size_t found(uint32_t recv_ifindex, const char *destination, std::optional<uint32_t> index = bound)
{
    monitor_rig rig{bound_options(index)};
    feed(rig, service_response("Gate"), arriving_on(rig.peer.socket(), destination, recv_ifindex));
    return rig.reported("Gate");
}

std::size_t queried(uint32_t recv_ifindex, const char *destination)
{
    querier_rig rig{response_mode::unicast, bound_options()};
    feed(rig, service_response("Gate"), arriving_on(rig.peer.socket(), destination, recv_ifindex));
    return rig.reported("Gate");
}

bool answered(uint32_t recv_ifindex, const char *destination)
{
    server_rig rig{service_options{}, bound_options()};
    feed(rig, service_query(), arriving_on(rig.peer.socket(), destination, recv_ifindex));
    return rig.peer.delay_timer().has_pending() || !rig.peer.socket().sent_packets().empty();
}

}

TEST_CASE("a peer bound to an interface ignores multicast that arrived on another interface",
          "[gate][attribution]")
{
    CHECK(found(3, "224.0.0.251") == 0);
    CHECK_FALSE(answered(3, "224.0.0.251"));
}

TEST_CASE("a peer bound to an interface takes multicast from that interface or of unknown interface",
          "[gate][attribution]")
{
    CHECK(found(bound, "224.0.0.251") == 1);
    CHECK(found(0, "224.0.0.251") == 1);
    CHECK(answered(bound, "224.0.0.251"));
    CHECK(answered(0, "224.0.0.251"));
}

TEST_CASE("the interface rule leaves unicast and unknown destinations to the on-link rule", "[gate][attribution]")
{
    loopback_index();
    CHECK(queried(3, "127.0.0.1") == 1);
    CHECK(found(3, nullptr) == 1);
    CHECK(answered(3, "127.0.0.1"));
    CHECK(answered(3, nullptr));
}

TEST_CASE("an unbound peer takes multicast from every interface", "[gate][attribution]")
{
    CHECK(found(3, "224.0.0.251", std::nullopt) == 1);
}

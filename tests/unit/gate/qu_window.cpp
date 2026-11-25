#include "helpers.h"
#include "qu_packets.h"

#include <catch2/catch_test_macros.hpp>

namespace {

recv_metadata on_link_unicast(const querier_rig &rig)
{
    return arriving(rig.peer.socket(), endpoint{"127.0.0.2", mdns_port}, address_of("127.0.0.1"), index_of_127_0_0_1());
}

}

TEST_CASE("a QM querier ignores a unicast response that answers its question", "[gate][qu-window][querier]")
{
    querier_rig rig{response_mode::multicast};
    feed(rig, service_response("Unasked"), on_link_unicast(rig));

    CHECK(rig.reported("Unasked") == 0);
}

TEST_CASE("a QU querier ignores a unicast response whose answer names another owner", "[gate][qu-window][querier]")
{
    querier_rig rig{response_mode::unicast};
    const std::vector<std::byte> response =
        answer_packet({{"_ipp._tcp.local.", ptr_type, in_class, "Other._ipp._tcp.local."}},
                      {{"_http._tcp.local.", ptr_type, in_class, "Other._http._tcp.local."}});
    feed(rig, response, on_link_unicast(rig));

    CHECK(rig.reported("Other") == 0);
}

TEST_CASE("a QU querier reports a unicast response that answers its question in another letter case",
          "[gate][qu-window][querier]")
{
    querier_rig rig{response_mode::unicast};
    const std::vector<std::byte> response =
        answer_packet({{"_HTTP._Tcp.LOCAL.", ptr_type, in_class, "Asked._http._tcp.local."}});
    feed(rig, response, on_link_unicast(rig));

    CHECK(rig.reported("Asked") == 1);
}

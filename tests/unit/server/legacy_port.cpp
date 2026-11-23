#include "fixture.h"
#include "query_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <vector>
#include <cstdint>

namespace {

struct custom_port_server
{
    custom_port_server()
        : ex{}
        , server{ex, make_test_info(), {}, socket_options{.multicast_group = endpoint{"224.0.0.251", 5454}}}
    {
        server.async_start();
        advance_to_live(server);
        server.socket().clear_sent();
    }

    void query_from(const endpoint &sender)
    {
        server.socket().inject_receive(sender, make_ptr_query("_http._tcp.local."));
    }

    const std::vector<sent_packet> &sent() const { return server.socket().sent_packets(); }

    mock_executor ex;
    basic_service_server<mock_policy> server;
};

}

TEST_CASE("a server on a custom group port answers a query from port 5353 as a legacy query",
          "[service_server][legacy_unicast][port]")
{
    custom_port_server rig;
    const endpoint sender{"192.0.2.20", 5353};
    rig.query_from(sender);

    CHECK(sent_to(rig.sent(), sender));
    CHECK_FALSE(rig.server.delay_timer().has_pending());
}

TEST_CASE("a server on a custom group port answers a query from that port by multicast",
          "[service_server][legacy_unicast][port]")
{
    custom_port_server rig;
    const endpoint sender{"192.0.2.20", 5454};
    rig.query_from(sender);

    CHECK_FALSE(sent_to(rig.sent(), sender));
    REQUIRE(rig.server.delay_timer().has_pending());
    rig.server.delay_timer().fire();
    CHECK(sent_to(rig.sent(), endpoint{"224.0.0.251", 5454}));
}

TEST_CASE("a query from port 0 is answered as a legacy query", "[service_server][legacy_unicast][port]")
{
    server_fixture f;
    f.go_live();
    f.clear_sent();
    const endpoint sender{"192.0.2.20", 0};
    f.inject(sender, make_ptr_query("_http._tcp.local."));

    CHECK(sent_to(f.sent(), sender));
    CHECK_FALSE(f.server.delay_timer().has_pending());
}

#include "helpers.h"

#include "mdnspp/socket_options.h"

#include "mdnspp/detail/gate_rules.h"
#include "mdnspp/detail/transport_traits.h"

#include "mdnspp/default/default_socket.h"

#include "mdnspp/inproc/inproc_socket.h"
#include "mdnspp/inproc/inproc_harness.h"
#include "mdnspp/inproc/inproc_socket_options.h"

#ifdef MDNSPP_ENABLE_ENCRYPT
#include "mdnspp/encrypt/encrypted_socket.h"
#endif

#include <catch2/generators/catch_generators.hpp>
#include <catch2/catch_test_macros.hpp>
#include <catch2/catch_template_test_macros.hpp>

#include <string>
#include <cstdint>
#include <utility>
#include <optional>
#include <algorithm>
#include <string_view>

using mdnspp::detail::is_in_process_v;
using mdnspp::inproc::inproc_socket;

namespace {

service_options flag_conflict(bool &conflict)
{
    service_options opts;
    opts.on_conflict = [&conflict](std::string_view, uint32_t, conflict_type) -> std::optional<std::string>
    {
        conflict = true;
        return "Renamed._http._tcp.local.";
    };
    return opts;
}

std::vector<std::byte> rival_claim()
{
    service_info rival = gate_service("Gate");
    rival.port = 9999;
    return detail::build_dns_response(rival, dns_type::srv, service_options{});
}

}

TEST_CASE("the source port rule passes a response from another port only for an in-process transport",
          "[gate][port]")
{
    recv_metadata meta;
    meta.sender = endpoint{"192.0.2.10", 40000};
    CHECK_FALSE(detail::response_port_accepted(meta, mdns_port, false));
    CHECK(detail::response_port_accepted(meta, mdns_port, true));
    meta.sender.port = mdns_port;
    CHECK(detail::response_port_accepted(meta, mdns_port, false));
}

TEMPLATE_TEST_CASE("a peer ignores a response from a port other than the multicast port", "[gate][port]",
                   querier_rig, observer_rig, monitor_rig, discovery_rig)
{
    const uint16_t port = GENERATE(uint16_t{40000}, uint16_t{0});
    TestType rig;
    feed(rig, service_response("Dropped"), sent_from_port(rig.peer.socket(), port));
    feed(rig, service_response("Kept"), sent_from_port(rig.peer.socket(), mdns_port));

    CHECK(rig.reported("Dropped") == 0);
    CHECK(rig.reported("Kept") == 1);
}

TEST_CASE("the source port rule follows the configured multicast port", "[gate][port][querier]")
{
    mock_executor ex;
    basic_querier<mock_policy> peer{ex, query_options{.silence_timeout = 500ms},
                                    socket_options{.multicast_group = endpoint{"224.0.0.251", 5454}}};
    peer.async_query("_http._tcp.local.", dns_type::ptr, [](std::error_code, std::vector<mdns_record_variant>) {});
    peer.socket().inject_receive(sent_from_port(peer.socket(), mdns_port), service_response("Dropped"));
    peer.socket().inject_receive(sent_from_port(peer.socket(), 5454), service_response("Kept"));

    CHECK(count_instance(peer.results(), "Dropped") == 0);
    CHECK(count_instance(peer.results(), "Kept") == 1);
}

TEST_CASE("a server ignores a conflicting response from a port other than the multicast port",
          "[gate][port][server]")
{
    bool conflict = false;
    server_rig rig{flag_conflict(conflict)};
    feed(rig, rival_claim(), sent_from_port(rig.peer.socket(), 40000));
    CHECK_FALSE(conflict);

    feed(rig, rival_claim(), sent_from_port(rig.peer.socket(), mdns_port));
    CHECK(conflict);
}

TEST_CASE("a query from a port other than the multicast port still reaches the server", "[gate][port][server]")
{
    server_rig rig;
    feed(rig, service_query(), sent_from_port(rig.peer.socket(), 40000));

    const endpoint legacy{"192.0.2.10", 40000};
    CHECK(std::ranges::any_of(rig.peer.socket().sent_packets(), [&legacy](const sent_packet &p)
    {
        return p.dest == legacy;
    }));
}

TEST_CASE("only the in-process transport declares the in-process trait", "[gate][port][trait]")
{
    STATIC_REQUIRE(is_in_process_v<inproc_socket<test_clock>>);
    STATIC_REQUIRE_FALSE(is_in_process_v<mock_socket>);
    STATIC_REQUIRE_FALSE(is_in_process_v<default_socket>);
#ifdef MDNSPP_ENABLE_ENCRYPT
    STATIC_REQUIRE(is_in_process_v<encrypt::encrypted_socket<inproc_socket<test_clock>>>);
    STATIC_REQUIRE_FALSE(is_in_process_v<encrypt::encrypted_socket<mock_socket>>);
#endif
}

TEST_CASE("an in-process querier takes the answer of an in-process server on another port", "[gate][port][inproc]")
{
    mdnspp::inproc::inproc_harness h;
    mdnspp::inproc::inproc_socket_options server_socket;
    server_socket.port_override = 40000;
    auto server = h.make_server(gate_service("Gate"), {}, std::move(server_socket));
    server.async_start();
    h.advance_to_live(server);

    auto querier = h.make_querier(query_options{.silence_timeout = 500ms});
    querier.async_query("_http._tcp.local.", dns_type::ptr, [](std::error_code, std::vector<mdns_record_variant>) {});
    h.advance(200ms);
    h.advance(200ms);

    CHECK(count_instance(querier.results(), "Gate") == 1);
}

#include "inproc_bus/helpers.h"
#include "inproc_bus/ttl_helpers.h"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <string>
#include <cstdint>
#include <string_view>

namespace {

service_info dual_stack_service(std::string_view name, std::string_view host, uint16_t port)
{
    service_info info = make_service(name, "_http._tcp.local.", host, port);
    info.address_ipv6 = "::1";
    return info;
}

void check_ttls(const std::map<std::string, uint32_t> &ttls, uint32_t ptr, uint32_t srv, uint32_t a, uint32_t aaaa)
{
    REQUIRE(ttls.count("ptr") > 0);
    REQUIRE(ttls.count("srv") > 0);
    REQUIRE(ttls.count("a") > 0);
    REQUIRE(ttls.count("aaaa") > 0);

    CHECK(ttls.at("ptr") == ptr);
    CHECK(ttls.at("srv") == srv);
    CHECK(ttls.at("a") == a);
    CHECK(ttls.at("aaaa") == aaaa);
}

}

TEST_CASE("Per-type TTLs appear in wire responses", "[inproc][ttl]")
{
    inproc_harness h;
    inproc::inproc_socket_options srv_sock;
    srv_sock.multicast_loopback = loopback_mode::disabled;
    auto server = h.make_server(dual_stack_service("PerTypeTtl._http._tcp.local.", "pertypettl.local.", 8080),
                                distinct_ttl_opts(), std::move(srv_sock));
    ttl_collector ttls{"PerTypeTtl", "pertypettl", true};
    live_observer obs{h, ttls.options()};

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    check_ttls(ttls.ttl_by_type, 100u, 200u, 400u, 500u);
}

TEST_CASE("Goodbye uses TTL=0 for all record types", "[inproc][ttl]")
{
    inproc_harness h;
    service_options srv_opts = distinct_ttl_opts();
    srv_opts.send_goodbye = true;
    auto server = h.make_server(dual_stack_service("GbyeTtl._http._tcp.local.", "gbyettl.local.", 9090),
                                std::move(srv_opts));
    ttl_collector ttls{"GbyeTtl", "gbyettl", false};
    live_observer obs{h, ttls.options()};

    server.async_start();
    h.advance_to_live(server);
    h.executor.drain();

    ttls.capture = true;
    server.stop();
    h.executor.drain();

    check_ttls(ttls.ttl_by_type, 0u, 0u, 0u, 0u);
}

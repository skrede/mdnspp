#include "helpers.h"

#include "support/skip_or_fail.h"
#include "support/ipv6_interface.h"

#include "mdnspp/policy.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_querier.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/socket_options.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_discovery.h"

#include <cstdint>
#include <system_error>

static_assert(mdnspp::policy_like<mdnspp::default_policy>, "default_policy must satisfy policy_like");
static_assert(mdnspp::socket_like<mdnspp::default_socket>, "default_socket must satisfy socket_like");
static_assert(mdnspp::timer_like<mdnspp::default_timer>, "default_timer must satisfy timer_like");
static_assert(std::constructible_from<mdnspp::default_socket, mdnspp::default_context &, const mdnspp::socket_options &>,
              "default_socket must be constructible from (context, socket_options)");
static_assert(std::constructible_from<mdnspp::default_socket, mdnspp::default_context &, const mdnspp::socket_options &,
                                      std::error_code &>,
              "default_socket must be constructible from (context, socket_options, error_code)");

static_assert(sizeof(mdnspp::basic_observer<mdnspp::default_policy>) > 0, "basic_observer<default_policy> must be a complete type");
static_assert(sizeof(mdnspp::basic_service_discovery<mdnspp::default_policy>) > 0, "basic_service_discovery<default_policy> must be a complete type");
static_assert(sizeof(mdnspp::basic_querier<mdnspp::default_policy>) > 0, "basic_querier<default_policy> must be a complete type");
static_assert(sizeof(mdnspp::basic_service_server<mdnspp::default_policy>) > 0, "basic_service_server<default_policy> must be a complete type");

TEST_CASE("default_policy satisfies policy_like concept (compile-time)", "[concept][conformance][native]")
{
    SUCCEED("default_policy static_assert passed at compile time");
}

TEST_CASE("default_socket with default socket_options", "[native][socket][socket_options]")
{
    mdnspp::default_context ctx;
    construct_or_skip("default_socket with socket_options", [&]
    {
        mdnspp::socket_options opts{};
        mdnspp::default_socket sock{ctx, opts};
    });
    SUCCEED("default_socket constructed with default socket_options (INADDR_ANY, TTL=255)");
}

TEST_CASE("default_socket with socket_options and error_code", "[native][socket][socket_options]")
{
    mdnspp::default_context ctx;
    mdnspp::socket_options opts{};
    std::error_code ec;
    mdnspp::default_socket sock{ctx, opts, ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("default_socket non-throwing construction failed: " + ec.message());
    SUCCEED("default_socket constructed with default socket_options via error_code overload");
}

TEST_CASE("default_socket construction joins multicast group", "[native][socket]")
{
    mdnspp::default_context ctx;
    construct_or_skip("default_socket", [&] { mdnspp::default_socket sock{ctx}; });
    SUCCEED("default_socket constructed and multicast group 224.0.0.251:5353 joined");
}

TEST_CASE("basic_observer instantiates with default_policy", "[native][policy][instantiation]")
{
    mdnspp::default_context ctx;
    construct_or_skip("observer<default_policy>", [&]
    {
        mdnspp::basic_observer<mdnspp::default_policy> obs{
            ctx, mdnspp::observer_options{.on_record = [](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &) {}}
        };
    });
    SUCCEED("observer<default_policy> constructed");
}

TEST_CASE("basic_service_discovery instantiates with default_policy", "[native][policy][instantiation]")
{
    mdnspp::default_context ctx;
    construct_or_skip("service_discovery<default_policy>", [&]
    {
        mdnspp::basic_service_discovery<mdnspp::default_policy> sd{ctx};
    });
    SUCCEED("service_discovery<default_policy> constructed");
}

TEST_CASE("basic_querier instantiates with default_policy", "[native][policy][instantiation]")
{
    mdnspp::default_context ctx;
    construct_or_skip("querier<default_policy>", [&] { mdnspp::basic_querier<mdnspp::default_policy> q{ctx}; });
    SUCCEED("querier<default_policy> constructed");
}

TEST_CASE("basic_service_server instantiates with default_policy", "[native][policy][instantiation]")
{
    mdnspp::default_context ctx;
    mdnspp::service_info info;
    info.service_name = "TestService._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "testhost.local.";
    info.port = 8080;
    construct_or_skip("service_server<default_policy>", [&]
    {
        mdnspp::basic_service_server<mdnspp::default_policy> srv{ctx, info};
    });
    SUCCEED("service_server<default_policy> constructed");
}

TEST_CASE("default_socket reports the interface index it is bound to", "[native][socket][socket_options]")
{
    const uint32_t loopback = mdnspp::test_support::loopback_ipv6_interface().index;
    mdnspp::socket_options opts = mdnspp::test_support::ipv6_group_options();
    opts.interface_index = loopback;
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket sock{ctx, opts, ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("IPv6 default_socket construction on loopback failed: " + ec.message());
    CHECK(sock.interface_index() == loopback);
}

TEST_CASE("an unbound default_socket reports interface index 0", "[native][socket][socket_options]")
{
    mdnspp::default_context ctx;
    std::error_code ec;
    mdnspp::default_socket sock{ctx, mdnspp::socket_options{.multicast_group = mdnspp::endpoint{"224.0.0.251", 0}}, ec};
    if(ec)
        mdnspp::test_support::skip_or_fail("default_socket construction failed: " + ec.message());
    CHECK(sock.interface_index() == 0);
}

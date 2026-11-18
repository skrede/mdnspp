#include "support/construct_or_skip.h"

#include "mdnspp/asio.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_service_monitor.h"

#include <asio.hpp>

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <cstdint>
#include <string_view>
#include <system_error>

using mdnspp::asio_policy;
using mdnspp::test_support::construct_or_skip;

namespace {

mdnspp::service_info destroy_test_info()
{
    mdnspp::service_info info;
    info.service_name = "DestroyTest._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname = "destroyhost.local.";
    info.port = 8080;
    info.address_ipv4 = "192.168.1.10";
    return info;
}

template <typename Peer, typename Make, typename Start>
void destroy_with_pending_receive(std::string_view what, Make make, Start start)
{
    asio::io_context io;
    construct_or_skip(what, [&]
    {
        auto peer = make(io);
        start(*peer);
    });
    io.run();
    SUCCEED();
}

}

TEST_CASE("destroying an observer with a pending receive is safe", "[asio][lifetime]")
{
    int32_t records = 0;
    int32_t completions = 0;
    destroy_with_pending_receive<mdnspp::basic_observer<asio_policy>>(
        "observer",
        [&records](asio::io_context &io)
        {
            mdnspp::observer_options opts;
            opts.on_record = [&records](const mdnspp::endpoint &, const mdnspp::mdns_record_variant &) { ++records; };
            return std::make_unique<mdnspp::basic_observer<asio_policy>>(io, std::move(opts));
        },
        [&completions](auto &peer) { peer.async_observe([&completions](std::error_code) { ++completions; }); });
    REQUIRE(records == 0);
    REQUIRE(completions == 1);
}

TEST_CASE("destroying a querier with a pending receive is safe", "[asio][lifetime]")
{
    destroy_with_pending_receive<mdnspp::basic_querier<asio_policy>>(
        "querier",
        [](asio::io_context &io) { return std::make_unique<mdnspp::basic_querier<asio_policy>>(io); },
        [](auto &peer) { peer.async_query("_http._tcp.local.", mdnspp::dns_type::ptr, [](std::error_code, auto) {}); });
}

TEST_CASE("destroying a discovery with a pending receive is safe", "[asio][lifetime]")
{
    destroy_with_pending_receive<mdnspp::basic_service_discovery<asio_policy>>(
        "discovery",
        [](asio::io_context &io) { return std::make_unique<mdnspp::basic_service_discovery<asio_policy>>(io); },
        [](auto &peer) { peer.async_discover("_http._tcp.local.", [](std::error_code, auto) {}); });
}

TEST_CASE("destroying a monitor with a pending receive is safe", "[asio][lifetime]")
{
    destroy_with_pending_receive<mdnspp::basic_service_monitor<asio_policy>>(
        "monitor",
        [](asio::io_context &io) { return std::make_unique<mdnspp::basic_service_monitor<asio_policy>>(io); },
        [](auto &peer) { peer.async_start([](std::error_code) {}); });
}

TEST_CASE("destroying a server with a pending receive is safe", "[asio][lifetime]")
{
    destroy_with_pending_receive<mdnspp::basic_service_server<asio_policy>>(
        "server",
        [](asio::io_context &io)
        { return std::make_unique<mdnspp::basic_service_server<asio_policy>>(io, destroy_test_info()); },
        [](auto &peer) { peer.async_start(); });
}

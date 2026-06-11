// tests/inproc_bus_auto_address_test.cpp
//
// async_start-time address resolution over the deterministic inproc bus
// (RFC 6762 §6.2). The inproc socket options carry an interface_address that
// does not exist on the host, so detail::resolve_advertised_addresses takes
// the address-only binding path: the announced A record must carry exactly
// the bound address — deterministic regardless of the host's real interfaces.
//
// TEST-01: a service_info::make()-created service announces an A record with
//          the socket's bound interface address.
// TEST-02: update_service_info re-resolves the addresses of an auto_address
//          replacement info.
// TEST-03: basic_nic_group stamps each per-NIC server with its slot's
//          interface address; the announced A record matches the slot.

#include "mdnspp/inproc/inproc_harness.h"

#include "mdnspp/records.h"
#include "mdnspp/service_info.h"
#include "mdnspp/basic_nic_group.h"
#include "mdnspp/observer_options.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/basic_service_server.h"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <variant>
#include <utility>

using namespace mdnspp;
using mdnspp::testing::test_clock;
using mdnspp::inproc::inproc_harness;
using mdnspp::inproc::inproc_socket_options;

namespace {

service_info make_auto_service()
{
    auto info = service_info::make("AutoAddr", "_test._tcp", 8080,
                                   {.hostname = "autohost"});
    REQUIRE(info.has_value());
    REQUIRE(info->auto_address);
    return std::move(*info);
}

// Collects the address of every A record observed for `owner`.
struct a_record_capture
{
    observer_options options(const dns_name &owner)
    {
        observer_options opts;
        opts.on_record = [this, owner](const endpoint &, const mdns_record_variant &rec)
        {
            if(const auto *a = std::get_if<record_a>(&rec); a && a->name == owner)
                addresses.push_back(a->address_string);
        };
        return opts;
    }

    std::vector<std::string> addresses;
};

}

TEST_CASE("make-created service announces the bound interface address", "[inproc][auto_address]")
{
    inproc_harness h;

    a_record_capture capture;
    auto obs = h.make_observer(capture.options("autohost.local."));
    obs.async_observe();
    h.executor.drain();

    inproc_socket_options sock_opts;
    sock_opts.interface_address = "10.1.2.3";
    auto server = h.make_server(make_auto_service(), {}, sock_opts);
    server.async_start();
    h.advance_to_live(server);

    REQUIRE_FALSE(capture.addresses.empty());
    for(const auto &address : capture.addresses)
        REQUIRE(address == "10.1.2.3");
}

TEST_CASE("update_service_info re-resolves auto addresses", "[inproc][auto_address]")
{
    inproc_harness h;

    a_record_capture capture;
    auto obs = h.make_observer(capture.options("autohost.local."));
    obs.async_observe();
    h.executor.drain();

    inproc_socket_options sock_opts;
    sock_opts.interface_address = "10.1.2.3";
    auto server = h.make_server(make_auto_service(), {}, sock_opts);
    server.async_start();
    h.advance_to_live(server);
    capture.addresses.clear();

    // The replacement info has unset addresses and auto_address set; the
    // update announcement must carry the re-resolved bound address.
    auto updated = make_auto_service();
    updated.txt_records = {{"v", "2"}};
    server.update_service_info(std::move(updated));
    h.advance(std::chrono::milliseconds{0});
    h.advance(std::chrono::milliseconds{1000}); // second update announcement

    REQUIRE_FALSE(capture.addresses.empty());
    for(const auto &address : capture.addresses)
        REQUIRE(address == "10.1.2.3");
}

TEST_CASE("nic_group stamps the per-NIC server with its slot's address", "[inproc][auto_address][nic_group]")
{
    inproc_harness h;

    auto nics = std::make_shared<std::vector<network_interface>>();
    {
        network_interface nic;
        nic.name = "nic1";
        nic.ipv4_address = "10.7.0.1";
        nic.index = 1;
        nic.is_up = true;
        nics->push_back(std::move(nic));
    }

    a_record_capture capture;
    auto obs = h.make_observer(capture.options("autohost.local."));
    obs.async_observe();
    h.executor.drain();

    basic_nic_group_options<inproc_test_policy> grp_opts;
    grp_opts.monitor_opts.poll_interval = std::chrono::milliseconds{100};
    grp_opts.monitor_opts.enumerator = [nics](std::error_code &ec)
    {
        ec.clear();
        return *nics;
    };

    std::vector<server_peer_options> srv_opts;
    srv_opts.push_back(server_peer_options{.info = make_auto_service()});

    basic_nic_group<inproc_test_policy, basic_service_server> grp{
        h.executor, std::move(grp_opts), std::move(srv_opts)};
    grp.start();
    h.executor.drain();

    // Drive the per-NIC server through probe and announce.
    h.advance(std::chrono::milliseconds{250});
    h.advance(std::chrono::milliseconds{250});
    h.advance(std::chrono::milliseconds{250});
    h.advance(std::chrono::milliseconds{250});
    h.advance(std::chrono::milliseconds{1000});

    REQUIRE_FALSE(capture.addresses.empty());
    for(const auto &address : capture.addresses)
        REQUIRE(address == "10.7.0.1"); // the slot's address, not a host NIC

    grp.stop();
}

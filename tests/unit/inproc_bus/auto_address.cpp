#include "inproc_bus/helpers.h"

#include "mdnspp/inproc/inproc_socket_options.h"

#include "mdnspp/basic_nic_group.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"

#include "mdnspp/detail/ip_address_ops.h"

#include <catch2/catch_test_macros.hpp>

#include <memory>
#include <string>
#include <vector>
#include <utility>
#include <variant>
#include <string_view>
#include <system_error>

using mdnspp::inproc::inproc_socket_options;

namespace {

service_info make_auto_service()
{
    auto info = service_info::make("AutoAddr", "_test._tcp", 8080, {.hostname = "autohost"});
    REQUIRE(info.has_value());
    REQUIRE(info->auto_address);
    return std::move(*info);
}

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

// The address exists on no host interface, so address resolution takes the address-only binding path and the
// announcement carries exactly this address, whatever the host's interfaces are (RFC 6762 section 6.2).
inproc_socket_options bound_to(std::string address)
{
    inproc_socket_options opts;
    opts.interface_address = std::move(address);
    return opts;
}

void require_only_address(const a_record_capture &capture, std::string_view expected)
{
    REQUIRE_FALSE(capture.addresses.empty());
    for(const auto &address : capture.addresses)
        REQUIRE(address == expected);
}

basic_nic_group_options<inproc_test_policy> single_nic_opts()
{
    network_interface nic;
    nic.name = "nic1";
    nic.addresses.push_back({*detail::parse_ip_address("10.7.0.1"), 24});
    nic.index = 1;
    nic.is_up = true;
    auto nics = std::make_shared<std::vector<network_interface>>();
    nics->push_back(std::move(nic));

    basic_nic_group_options<inproc_test_policy> opts;
    opts.monitor_opts.poll_interval = 100ms;
    opts.monitor_opts.enumerator = [nics](std::error_code &ec)
    {
        ec.clear();
        return *nics;
    };
    return opts;
}

}

TEST_CASE("make-created service announces the bound interface address", "[inproc][auto_address]")
{
    inproc_harness h;
    a_record_capture capture;
    live_observer obs{h, capture.options("autohost.local.")};
    auto server = h.make_server(make_auto_service(), {}, bound_to("10.1.2.3"));
    server.async_start();
    h.advance_to_live(server);
    require_only_address(capture, "10.1.2.3");
}

TEST_CASE("update_service_info re-resolves auto addresses", "[inproc][auto_address]")
{
    inproc_harness h;
    a_record_capture capture;
    live_observer obs{h, capture.options("autohost.local.")};
    auto server = h.make_server(make_auto_service(), {}, bound_to("10.1.2.3"));
    server.async_start();
    h.advance_to_live(server);
    capture.addresses.clear();

    // The replacement has unset addresses and auto_address set, so the update announcements carry the re-resolved
    // bound address.
    auto updated = make_auto_service();
    updated.txt_records = {{"v", "2"}};
    server.update_service_info(std::move(updated));
    h.advance(0ms);
    h.advance(1000ms);
    require_only_address(capture, "10.1.2.3");
}

TEST_CASE("nic_group stamps the per-NIC server with its slot's address", "[inproc][auto_address][nic_group]")
{
    inproc_harness h;
    a_record_capture capture;
    live_observer obs{h, capture.options("autohost.local.")};
    std::vector<server_peer_options> srv_opts;
    srv_opts.push_back(server_peer_options{.info = make_auto_service()});
    basic_nic_group<inproc_test_policy, basic_service_server> grp{h.executor, single_nic_opts(), std::move(srv_opts)};
    grp.start();
    h.executor.drain();

    h.advance(250ms);
    finish_ceremony(h);
    // The slot's address, not one of the host's interfaces.
    require_only_address(capture, "10.7.0.1");
    grp.stop();
}

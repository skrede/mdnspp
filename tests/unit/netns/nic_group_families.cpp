#include "netns/bound_peers.h"

#include "support/netns.h"

#include "mdnspp/defaults.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include <catch2/catch_test_macros.hpp>

#include <map>
#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <utility>

using mdnspp::test_support::require_netns_harness;

namespace {

using peer_server = mdnspp::basic_service_server<mdnspp::default_policy>;

mdnspp::service_info link_service(const std::string &name, const std::string &v4, const std::string &v6)
{
    mdnspp::service_info info = attribution_service();
    info.service_name = name + "._http._tcp.local.";
    info.hostname = name + ".local.";
    info.address_ipv4 = v4;
    info.address_ipv6 = v6;
    return info;
}

mdnspp::service_options quick_probe()
{
    return mdnspp::service_options{.probe_initial_delay_max = std::chrono::milliseconds{0}};
}

std::unique_ptr<peer_server> start_peer_in(mdnspp::default_context &ctx, const std::string &netns,
                                           const std::string &device, const std::string &group,
                                           mdnspp::service_info info)
{
    std::unique_ptr<peer_server> server;
    mdnspp::test_support::run_in_netns(
        netns,
        [&] { server = std::make_unique<peer_server>(ctx, std::move(info), quick_probe(), bound_to(device, group)); });
    server->async_start();
    return server;
}

class link_peers
{
public:
    explicit link_peers(mdnspp::default_context &ctx)
        : m_servers{}
    {
        add(ctx, "p0", "q0", "Zero", {"10.20.0.2", ""}, {"", "fd20:0::2"});
        add(ctx, "p1", "q1", "One", {"10.20.1.2", ""}, {"", "fd20:1::2"});
    }

private:
    std::vector<std::unique_ptr<peer_server>> m_servers;

    void add(mdnspp::default_context &ctx, const std::string &netns, const std::string &device, const std::string &name,
             std::pair<std::string, std::string> v4, std::pair<std::string, std::string> v6)
    {
        m_servers.push_back(start_peer_in(ctx, netns, device, "224.0.0.251", link_service(name, v4.first, v4.second)));
        m_servers.push_back(start_peer_in(ctx, netns, device, "ff02::fb", link_service(name, v6.first, v6.second)));
    }
};

struct heard_services
{
    struct entry
    {
        std::string name;
        std::vector<std::string> v4;
        std::vector<std::string> v6;
    };

    void note(const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc)
    {
        auto &seen = by_nic[nic.name];
        seen.name = svc.instance_name.str();
        seen.v4 = svc.ipv4_addresses;
        seen.v6 = svc.ipv6_addresses;
    }

    std::map<std::string, entry> by_nic;
};

bool is_dut_link(const mdnspp::network_interface &nic)
{
    return nic.name == "d0" || nic.name == "d1";
}

mdnspp::nic_group_options default_policy_options(heard_services &heard)
{
    mdnspp::nic_group_options opts;
    opts.interface_filter = is_dut_link;
    opts.on_found = [&heard](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc)
    { heard.note(nic, svc); };
    opts.on_updated = [&heard](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc,
                               mdnspp::update_event, mdnspp::dns_type) { heard.note(nic, svc); };
    return opts;
}

heard_services discover_with_default_policy()
{
    mdnspp::default_context ctx;
    link_peers peers{ctx};
    heard_services heard;
    std::vector<mdnspp::monitor_options> monitors(1);
    mdnspp::nic_group<mdnspp::basic_service_monitor> grp{ctx, default_policy_options(heard), std::move(monitors)};
    grp.start();
    grp.watch("_http._tcp.local.");
    run_for(ctx, std::chrono::milliseconds{3000});
    grp.stop();
    return heard;
}

}

TEST_CASE("a default-policy nic_group finds a peer's service on each link", "[netns][nic_group]")
{
    require_netns_harness();
    const heard_services heard = discover_with_default_policy();

    REQUIRE(heard.by_nic.contains("d0"));
    REQUIRE(heard.by_nic.contains("d1"));
    CHECK(heard.by_nic.at("d0").name == "Zero._http._tcp.local.");
    CHECK(heard.by_nic.at("d1").name == "One._http._tcp.local.");
}

TEST_CASE("a default-policy nic_group unites the IPv4 and IPv6 addresses of a dual-family service on each link",
          "[netns][nic_group]")
{
    require_netns_harness();
    const heard_services heard = discover_with_default_policy();

    REQUIRE(heard.by_nic.contains("d0"));
    REQUIRE(heard.by_nic.contains("d1"));
    CHECK(heard.by_nic.at("d0").v4 == std::vector<std::string>{"10.20.0.2"});
    CHECK(heard.by_nic.at("d0").v6 == std::vector<std::string>{"fd20::2"});
    CHECK(heard.by_nic.at("d1").v4 == std::vector<std::string>{"10.20.1.2"});
    CHECK(heard.by_nic.at("d1").v6 == std::vector<std::string>{"fd20:1::2"});
}

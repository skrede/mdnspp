#ifndef HPP_GUARD_MDNSPP_NIC_GROUP_FIXTURE_H
#define HPP_GUARD_MDNSPP_NIC_GROUP_FIXTURE_H

#include "mdnspp/inproc/inproc_policy.h"

#include "mdnspp/service_info.h"
#include "mdnspp/basic_observer.h"
#include "mdnspp/basic_nic_group.h"
#include "mdnspp/monitor_options.h"
#include "mdnspp/resolved_service.h"
#include "mdnspp/network_interface.h"
#include "mdnspp/nic_group_options.h"
#include "mdnspp/basic_service_server.h"
#include "mdnspp/basic_service_monitor.h"

#include <chrono>
#include <memory>
#include <string>
#include <vector>
#include <cstdint>
#include <utility>
#include <algorithm>
#include <system_error>

using namespace mdnspp;
using namespace std::chrono_literals;
using mdnspp::testing::test_clock;
using mdnspp::inproc::inproc_bus;
using mdnspp::inproc::inproc_executor;

using inproc_server = basic_service_server<inproc_test_policy>;
using monitor_group = basic_nic_group<inproc_test_policy, basic_service_monitor>;
using server_group = basic_nic_group<inproc_test_policy, basic_service_server>;
using observer_group = basic_nic_group<inproc_test_policy, basic_observer>;
using group_options = basic_nic_group_options<inproc_test_policy>;
using found_list = std::vector<std::pair<std::string, std::string>>;

inline network_interface make_nic(uint32_t index, std::string name, std::string ipv4)
{
    network_interface nic;
    nic.name = std::move(name);
    nic.ipv4_address = std::move(ipv4);
    nic.index = index;
    nic.is_up = true;
    return nic;
}

inline service_info make_service(std::string name)
{
    service_info info;
    info.service_name = std::move(name);
    info.service_type = "_test._tcp.local.";
    info.hostname = "host.local.";
    info.port = 8080;
    info.address_ipv4 = "192.168.1.1";
    return info;
}

inline std::vector<monitor_options> one_monitor()
{
    std::vector<monitor_options> opts;
    opts.push_back(monitor_options{});
    return opts;
}

inline std::vector<std::string> sorted_interfaces(const found_list &found)
{
    std::vector<std::string> interfaces;
    for(const auto &[nic, instance] : found)
        interfaces.push_back(nic);
    std::ranges::sort(interfaces);
    return interfaces;
}

// The enumerator seam supplies a fixed interface list, and every per-NIC socket registers on the one shared bus, so
// multicast traffic reaches every per-NIC instance like a service reachable on every interface.
struct group_fixture
{
    group_fixture()
        : bus{}
        , executor{bus}
        , nics{std::make_shared<std::vector<network_interface>>()}
    {
        test_clock::reset();
        nics->push_back(make_nic(1, "nic1", "10.0.0.1"));
        nics->push_back(make_nic(2, "nic2", "10.0.1.1"));
    }

    group_options make_grp_opts()
    {
        group_options opts;
        opts.monitor_opts.poll_interval = 100ms;
        opts.monitor_opts.enumerator = [nics = nics](std::error_code &ec)
        {
            ec.clear();
            return *nics;
        };
        return opts;
    }

    group_options recording_grp_opts(found_list &found)
    {
        group_options opts = make_grp_opts();
        opts.on_found = [&found](const network_interface &nic, const resolved_service &svc)
        {
            found.emplace_back(nic.name, svc.instance_name.str());
        };
        return opts;
    }

    void advance(std::chrono::milliseconds d)
    {
        test_clock::advance(d);
        executor.drain();
    }

    template <typename Done>
    void advance_until(Done done, std::chrono::milliseconds step, int32_t max_steps)
    {
        for(int32_t i = 0; i < max_steps && !done(); ++i)
            advance(step);
    }

    // Steps a default-option server through the first-probe delay bound, two more probes, the conflict window and
    // the second announcement.
    void advance_to_live()
    {
        for(int32_t i = 0; i < 4; ++i)
            advance(250ms);
        advance(1000ms);
    }

    void start_watching(monitor_group &grp)
    {
        grp.watch("_test._tcp.local.");
        grp.start();
        executor.drain();
    }

    inproc_bus<test_clock> bus;
    inproc_executor<test_clock> executor;
    std::shared_ptr<std::vector<network_interface>> nics;
};

struct announced_service
{
    explicit announced_service(group_fixture &f)
        : server{f.executor, make_service("svc._test._tcp.local.")}
    {
        server.async_start();
        f.advance_to_live();
    }

    inproc_server server;
};

#endif

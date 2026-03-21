// Identify which network interface a service was discovered on.
//
// source_interface is populated by the nic_group monitor machinery —
// plain observer does not expose per-interface metadata. This example
// uses nic_group<basic_service_monitor> to discover HTTP services and
// prints the originating interface name and index for each.

#include <mdnspp/defaults.h>
#include <mdnspp/monitor_options.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::monitor_options opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name
                << " interface=" << svc.source_interface.name
                << " index=" << svc.source_interface.index
                << " at " << svc.hostname << ":" << svc.port << std::endl;
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name
                << " interface=" << svc.source_interface.name << std::endl;
        },
    };

    std::vector<mdnspp::monitor_options> opts_vec;
    opts_vec.push_back(std::move(opts));

    mdnspp::nic_group<mdnspp::basic_service_monitor> grp{
        ctx,
        mdnspp::nic_group_options{},
        std::move(opts_vec)
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    ctx.run();
}

// Monitor HTTP services across all network interfaces using nic_group.

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
                << " on " << svc.source_interface.name
                << " at " << svc.hostname << ":" << svc.port << std::endl;
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name
                << " on " << svc.source_interface.name << std::endl;
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

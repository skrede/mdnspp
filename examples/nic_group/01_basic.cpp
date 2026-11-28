// Monitor HTTP services across all network interfaces using nic_group.
// Discovery events are registered group-level and fire once per interface,
// with the originating network_interface passed as the leading parameter.

#include <mdnspp/defaults.h>
#include <mdnspp/monitor_options.h>

#include <vector>
#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::nic_group_options grp_opts{
        .on_found = [](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name
                << " on " << nic.name
                << " at " << svc.hostname << ":" << svc.port << std::endl;
        },
        .on_lost = [](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name
                << " on " << nic.name << std::endl;
        },
    };

    // Per-NIC options carry tuning only — callbacks are group-level (above).
    std::vector<mdnspp::monitor_options> opts_vec;
    opts_vec.push_back(mdnspp::monitor_options{});

    mdnspp::nic_group<mdnspp::basic_service_monitor> grp{
        ctx,
        std::move(grp_opts),
        std::move(opts_vec)
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    ctx.run();
}

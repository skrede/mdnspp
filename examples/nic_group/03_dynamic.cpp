// Runtime NIC group composition via basic_dynamic_nic_group builder pattern.
// Builder methods (monitor, announce, observe) must be called before start().
// watch() must be called after start().

#include <mdnspp/defaults.h>
#include <mdnspp/monitor_options.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::dynamic_nic_group grp{ctx};

    std::vector<mdnspp::monitor_options> mon_opts;
    mon_opts.push_back({
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name
                << " on " << svc.source_interface.name
                << " at " << svc.hostname << ":" << svc.port << std::endl;
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name << std::endl;
        },
    });

    grp.monitor(std::move(mon_opts));

    grp.start();
    grp.watch("_http._tcp.local.");

    ctx.run();
}

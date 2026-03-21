// Announce an HTTP service and monitor for others across all network interfaces.

#include <mdnspp/defaults.h>
#include <mdnspp/monitor_options.h>
#include <mdnspp/nic_group_options.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::monitor_options mon_opts{
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
    };

    mdnspp::server_peer_options srv_opts{
        .info = {
            .service_name = "MyApp._http._tcp.local.",
            .service_type = "_http._tcp.local.",
            .hostname     = "myhost.local.",
            .port         = 8080,
        },
    };

    std::vector<mdnspp::monitor_options> mon_opts_vec;
    mon_opts_vec.push_back(std::move(mon_opts));

    std::vector<mdnspp::server_peer_options> srv_opts_vec;
    srv_opts_vec.push_back(std::move(srv_opts));

    mdnspp::nic_group<mdnspp::basic_service_monitor, mdnspp::basic_service_server> grp{
        ctx,
        mdnspp::nic_group_options{},
        std::move(mon_opts_vec),
        std::move(srv_opts_vec)
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    ctx.run();
}

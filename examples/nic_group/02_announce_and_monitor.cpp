// Announce an HTTP service and monitor for others across all network interfaces.
// Monitor events are group-level and interface-stamped; the same service seen
// on two interfaces yields two on_found events with distinct interfaces.

#include <mdnspp/defaults.h>
#include <mdnspp/monitor_options.h>
#include <mdnspp/nic_group_options.h>

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

    mdnspp::server_peer_options srv_opts{
        .info = {
            .service_name = "MyApp._http._tcp.local.",
            .service_type = "_http._tcp.local.",
            .hostname     = "myhost.local.",
            .port         = 8080,
        },
        // server_peer_options::service callbacks (on_conflict, on_query, ...)
        // are per-service and forwarded to every per-NIC server instance.
        .service = {
            .on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type, mdnspp::response_mode)
            {
                std::cout << "queried by " << sender.address << std::endl;
            },
        },
    };

    std::vector<mdnspp::monitor_options> mon_opts_vec;
    mon_opts_vec.push_back(mdnspp::monitor_options{});

    std::vector<mdnspp::server_peer_options> srv_opts_vec;
    srv_opts_vec.push_back(std::move(srv_opts));

    mdnspp::nic_group<mdnspp::basic_service_monitor, mdnspp::basic_service_server> grp{
        ctx,
        std::move(grp_opts),
        std::move(mon_opts_vec),
        std::move(srv_opts_vec)
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    ctx.run();
}

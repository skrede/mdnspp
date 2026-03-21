// Monitor HTTP services across all network interfaces using AsioPolicy nic_group.

#include <mdnspp/asio.h>
#include <mdnspp/basic_nic_group.h>
#include <mdnspp/monitor_options.h>
#include <mdnspp/nic_group_options.h>
#include <mdnspp/basic_service_monitor.h>

#include <iostream>

int main()
{
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

    asio::io_context io;
    mdnspp::basic_nic_group<mdnspp::AsioPolicy, mdnspp::basic_service_monitor> grp{
        io,
        mdnspp::nic_group_options{},
        std::move(opts_vec)
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    io.run();
}

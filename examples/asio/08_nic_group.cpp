// Monitor HTTP services across all network interfaces using asio_policy nic_group.
// Discovery events are registered group-level in basic_nic_group_options and
// fire once per interface, with the originating network_interface passed as
// the leading parameter. Per-NIC monitor_options carry tuning only --
// basic_nic_group rejects per-NIC options that carry callbacks.

#include <mdnspp/asio.h>
#include <mdnspp/basic_nic_group.h>
#include <mdnspp/monitor_options.h>
#include <mdnspp/nic_group_options.h>
#include <mdnspp/basic_service_monitor.h>

#include <vector>
#include <iostream>

int main()
{
    mdnspp::basic_nic_group_options<mdnspp::asio_policy> grp_opts{
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

    std::vector<mdnspp::monitor_options> opts_vec;
    opts_vec.push_back(mdnspp::monitor_options{});

    asio::io_context io;
    mdnspp::basic_nic_group<mdnspp::asio_policy, mdnspp::basic_service_monitor> grp{
        io,
        std::move(grp_opts),
        std::move(opts_vec)
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    io.run();
}

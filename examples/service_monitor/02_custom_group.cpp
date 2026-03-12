#include <mdnspp/defaults.h>

#include <iostream>

// Discover services on an isolated multicast group.

int main()
{
    mdnspp::context ctx;

    mdnspp::monitor_options opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << " at " << svc.hostname << ":" << svc.port << std::endl;
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name << std::endl;
        },
    };

    // Using a private multicast group creates an isolated discovery namespace: only peers configured with the same group and port will exchange traffic.
    // NB: THIS IS NON-STANDARD MDNS (mDNS protocol in/thru a non-mDNS multicast group/port)
    mdnspp::socket_options sock_opts{.multicast_group = mdnspp::endpoint{"239.255.100.1", 5354}};

    mdnspp::service_monitor monitor{ctx, std::move(opts), sock_opts};
    monitor.watch("_http._tcp.local.");
    monitor.async_start([&ctx](std::error_code ec)
    {
        if(ec)
        {
            std::cerr << "monitor error: " << ec.message() << std::endl;
            ctx.stop();
        }
    });

    ctx.run();
}

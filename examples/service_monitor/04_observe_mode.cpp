#include <mdnspp/defaults.h>

#include <iostream>

// Passively observe services without sending (re-)queries.
int main()
{
    mdnspp::context ctx;

    // observe mode only listens to multicast traffic (like an observer) -- no PTR queries are issued. Services are discovered when peers announce themselves.
    mdnspp::monitor_options opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "observed: " << svc.instance_name << " at " << svc.hostname << ":" << svc.port << std::endl;
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "gone: " << svc.instance_name << std::endl;
        },
        .mode = mdnspp::monitor_mode::observe,
    };

    mdnspp::service_monitor monitor{ctx, std::move(opts)};
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

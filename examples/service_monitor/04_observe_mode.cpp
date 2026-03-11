// Passively observe services without sending queries.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    // observe mode only listens to ambient multicast traffic -- no PTR queries
    // are issued. Services are discovered when peers announce them spontaneously.
    mdnspp::monitor_options opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "observed: " << svc.instance_name
                      << " at " << svc.hostname << ":" << svc.port << "\n";
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "gone: " << svc.instance_name << "\n";
        },
        .mode = mdnspp::monitor_mode::observe,
    };

    mdnspp::service_monitor mon{ctx, std::move(opts)};

    mon.watch("_http._tcp.local.");

    mon.async_start([&ctx](std::error_code ec)
    {
        if(ec)
        {
            std::cerr << "monitor error: " << ec.message() << "\n";
            ctx.stop();
        }
    });

    ctx.run();
}

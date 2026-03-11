// Continuously discover HTTP services on the local network.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::monitor_options opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name
                      << " at " << svc.hostname << ":" << svc.port << "\n";
        },
        .on_updated = [](const mdnspp::resolved_service &svc,
                         mdnspp::update_event event,
                         mdnspp::dns_type type)
        {
            std::cout << "updated: " << svc.instance_name
                      << " event=" << (event == mdnspp::update_event::added ? "added" : "removed")
                      << " type=" << to_string(type) << "\n";
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason reason)
        {
            const char *why = reason == mdnspp::loss_reason::timeout   ? "timeout"
                            : reason == mdnspp::loss_reason::goodbye   ? "goodbye"
                                                                       : "unwatched";
            std::cout << "lost: " << svc.instance_name << " reason=" << why << "\n";
        },
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

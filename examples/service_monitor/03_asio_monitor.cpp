// Service monitoring with standalone ASIO event loop.

#include <mdnspp/asio.h>
#include <mdnspp/monitor_options.h>
#include <mdnspp/basic_service_monitor.h>

#include <iostream>

int main()
{
    mdnspp::monitor_options opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name
                << " at " << svc.hostname << ":" << svc.port << std::endl;
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name << std::endl;
        },
    };

    asio::io_context io;
    mdnspp::basic_service_monitor<mdnspp::AsioPolicy> monitor{io, std::move(opts), mdnspp::socket_options{}};
    monitor.watch("_http._tcp.local.");
    monitor.async_start([](std::error_code ec)
    {
        if(ec)
            std::cerr << "monitor error: " << ec.message() << std::endl;
    });

    io.run();
}

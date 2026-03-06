// Serve an mDNS service using AsioPolicy.
// Responds to queries until Ctrl-C.
// Usage: ./mdnspp_example_asio_serve

#include <mdnspp/asio.h>
#include <mdnspp/basic_service_server.h>
#include <mdnspp/service_info.h>
#include <mdnspp/detail/dns_enums.h>

#include <iostream>

int main()
{
    asio::io_context io;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.69",
        .txt_records  = {{"path", "/index.html"}},
    };

    mdnspp::basic_service_server<mdnspp::AsioPolicy> srv{
        io,
        std::move(info),
        [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, bool unicast)
        {
            std::cout << sender.address << ":" << sender.port
                << " queried qtype=" << to_string(qtype)
                << (unicast ? " (unicast)" : " (multicast)") << "\n";
        }
    };

    asio::signal_set signals(io, SIGINT);
    signals.async_wait([&srv](std::error_code, int)
    {
        srv.stop();
    });

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (Ctrl-C to stop)\n";
    mdnspp::async_start(srv, [](std::error_code)
    {
    });
    io.run();
}

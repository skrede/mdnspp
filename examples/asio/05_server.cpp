#include <mdnspp/asio.h>
#include <mdnspp/service_info.h>
#include <mdnspp/basic_service_server.h>

#include <iostream>

// Serve an mDNS service using AsioPolicy.
// Responds to queries until Ctrl-C.

int main()
{
    asio::io_context io;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname = "myhost.local.",
        .port = 8080,
        .address_ipv4 = "192.168.1.69",
        .address_ipv6 = {},
        .txt_records = {{"path", "/index.html"}},
        .subtypes = {},
    };

    mdnspp::basic_service_server<mdnspp::AsioPolicy> srv{
        io,
        std::move(info),
        mdnspp::service_options{
            .on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
            {
                std::cout << sender.address << ":" << sender.port << " queried qtype=" << to_string(qtype) << " (" << to_string(mode) << ")" << std::endl;
            }
        }
    };

    asio::steady_timer timer(io, std::chrono::seconds(10));
    timer.async_wait([&srv, &io](std::error_code)
    {
        srv.stop();
        io.stop();
    });

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (Ctrl-C to stop)" << std::endl;
    srv.async_start();
    io.run();
}

#include <mdnspp/asio.h>
#include <mdnspp/service_info.h>
#include <mdnspp/basic_service_server.h>

#include <chrono>
#include <iostream>

// Serve an mDNS service using asio_policy.
// mdnspp::async_start() completes at the ready event -- once the service is
// probed and announced (live) -- or with the startup failure
// (mdns_error::probe_conflict and others). The server keeps serving after
// the token completes; here a 10 s timer then calls stop(), the teardown
// sends the goodbye packets, and io.run() returns when the event loop runs
// out of work.

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

    mdnspp::basic_service_server<mdnspp::asio_policy> srv{
        io,
        std::move(info),
        mdnspp::service_options{
            .on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
            {
                std::cout << sender.address << ":" << sender.port << " queried qtype=" << to_string(qtype) << " (" << to_string(mode) << ")" << std::endl;
            }
        }
    };

    asio::steady_timer stop_timer(io);

    std::cout << "Starting MyApp._http._tcp.local. on port 8080" << std::endl;
    mdnspp::async_start(srv, [&stop_timer, &srv](std::error_code ec)
    {
        if(ec)
        {
            std::cerr << "startup failed: " << ec.message() << std::endl;
            return; // on permanent failure the server has already torn down
        }
        std::cout << "Service live -- serving for 10 seconds" << std::endl;
        stop_timer.expires_after(std::chrono::seconds(10));
        stop_timer.async_wait([&srv](std::error_code) { srv.stop(); });
    });

    io.run();
    std::cout << "Server stopped" << std::endl;
}

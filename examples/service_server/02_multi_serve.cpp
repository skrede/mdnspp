#include <mdnspp/defaults.h>

#include <iostream>
#include <thread>

// Announce two mDNS services sharing a single context using DefaultPolicy.
// Demonstrates that multiple service_servers can coexist on one event loop.
// Auto-stops after 30 seconds.

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info http_info{
        .service_name = "WebApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname = "myhost.local.",
        .port = 8080,
        .address_ipv4 = "192.168.1.69",
        .address_ipv6 = {},
        .txt_records = {{"path", "/index.html"}},
        .subtypes = {},
    };

    mdnspp::service_info ssh_info{
        .service_name = "MyHost._ssh._tcp.local.",
        .service_type = "_ssh._tcp.local.",
        .hostname = "myhost.local.",
        .port = 22,
        .address_ipv4 = "192.168.1.69",
        .address_ipv6 = {},
        .txt_records = {},
        .subtypes = {},
    };

    mdnspp::service_server http_srv{
        ctx,
        std::move(http_info),
        mdnspp::service_options{
            .on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
            {
                std::cout << "[http] " << sender << " queried qtype=" << to_string(qtype)
                    << " (" << to_string(mode) << ")" << std::endl;
            }
        }
    };

    mdnspp::service_server ssh_srv{
        ctx,
        std::move(ssh_info),
        mdnspp::service_options{
            .on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
            {
                std::cout << "[ssh]  " << sender << " queried qtype=" << to_string(qtype)
                    << " (" << to_string(mode) << ")" << std::endl;
            }
        }
    };

    std::thread shutdown([&ctx]
    {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        ctx.stop();
    });

    std::cout << "Serving HTTP + SSH on shared context (30s then auto-stop)" << std::endl;
    http_srv.async_start();
    ssh_srv.async_start();
    ctx.run();

    shutdown.join();
}

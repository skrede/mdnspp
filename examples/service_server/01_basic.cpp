// Announce an HTTP service via mDNS using DefaultPolicy.
// Auto-stops after 30 seconds.

#include <mdnspp/defaults.h>

#include <thread>
#include <iostream>

int main()
{
    mdnspp::context ctx;

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

    mdnspp::service_server srv{
        ctx,
        std::move(info),
        mdnspp::service_options{
            .on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
            {
                std::cout << sender << " queried qtype=" << to_string(qtype)
                    << " (" << to_string(mode) << ")" << std::endl;
            }
        }
    };

    std::thread shutdown([&ctx]
    {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        ctx.stop();
    });

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (30s then auto-stop)" << std::endl;
    srv.async_start();
    ctx.run();

    shutdown.join();
}

// Announce an HTTP service via mDNS using DefaultPolicy.
// Auto-stops after 30 seconds.
// Usage: ./mdnspp_example_serve

#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>
#include <mdnspp/detail/dns_enums.h>

#include <iostream>
#include <thread>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.69",
        .txt_records  = {{"path", "/index.html"}},
    };

    mdnspp::service_server srv{ctx, std::move(info),
        [](mdnspp::dns_type qtype, mdnspp::endpoint sender, bool unicast)
        {
            std::cout << sender << " queried qtype=" << to_string(qtype)
                << (unicast ? " (unicast)" : " (multicast)") << "\n";
        }
    };

    std::jthread shutdown{[&ctx](std::stop_token) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        ctx.stop();
    }};

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (30s then auto-stop)\n";
    srv.async_start();
    ctx.run();
}

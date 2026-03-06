// Discover HTTP services on the local network using DefaultPolicy.
// Self-terminates after 3 seconds of silence.
// Usage: ./mdnspp_example_discover

#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{ctx, std::chrono::seconds(3),
        [](const mdnspp::mdns_record_variant &rec, const mdnspp::endpoint &sender)
        {
            std::visit([&](const auto &r) {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    sd.async_discover("_http._tcp.local.",
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
                std::cerr << "discovery error: " << ec.message() << "\n";
            else
                std::cout << "Discovery complete -- " << results.size() << " record(s)\n";
            ctx.stop();
        });

    ctx.run();
}

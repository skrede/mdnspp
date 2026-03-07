// Discover HTTP services on the local network using DefaultPolicy.
// Self-terminates after 3 seconds of silence.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{
        ctx,
        std::chrono::seconds(3),
        [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&](const auto &r)
            {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    sd.async_discover("_http._tcp.local.", [&ctx](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
    {
        if(ec)
            std::cerr << "Discovery error: " << ec.message() << "\n";
        else
            std::cout << "Discovery complete: " << results.size() << " record(s)\n";
        ctx.stop();
    });

    ctx.run();
}

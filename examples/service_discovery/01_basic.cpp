#include <mdnspp/defaults.h>

#include <iostream>

// Discover HTTP services on the local network using DefaultPolicy.
// Self-terminates after 3 seconds of silence.

int main()
{
    mdnspp::context ctx;
    mdnspp::service_discovery discovery{
        ctx,
        mdnspp::query_options{
            .on_record = [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&](const auto &r)
                {
                    std::cout << sender << " -> " << r << std::endl;
                }, rec);
            }
        }
    };

    discovery.async_discover("_http._tcp.local.", [&ctx](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
    {
        if(ec)
            std::cerr << "Discovery error: " << ec.message() << std::endl;
        else
            std::cout << "Discovery complete: " << results.size() << " record(s)" << std::endl;
        ctx.stop();
    });

    ctx.run();
}

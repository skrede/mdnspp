// Discovers services matching a specific subtype using DNS-SD subtype queries
// (RFC 6763 section 7.1). Searches for "_printer" subtypes of "_http._tcp.local.".

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{ctx};

    sd.async_discover_subtype("_http._tcp.local.", "_printer",
        [&ctx](std::error_code ec,
               const std::vector<mdnspp::mdns_record_variant> &results)
        {
            if(ec)
            {
                std::cerr << "Subtype discovery error: " << ec.message() << std::endl;
                ctx.stop();
                return;
            }

            std::cout << "Found " << results.size()
                << " record(s) for _printer subtype" << std::endl;
            ctx.stop();
        });

    ctx.run();
}

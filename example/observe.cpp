// Observe mDNS multicast traffic using DefaultPolicy.
// Prints each record to stdout, stops after 10 records.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;
    int count = 0;

    mdnspp::observer obs{
        ctx, {},
        [&](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&](const auto &r)
            {
                std::cout << sender << " -> " << r << "\n";
            }, rec);

            if(++count >= 10)
                obs.stop();
        }
    };

    obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();
}

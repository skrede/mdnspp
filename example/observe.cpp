// Observe mDNS multicast traffic using DefaultPolicy.
// Prints each record to stdout, stops after 10 records.
// Usage: ./mdnspp_example_observe

#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;
    int count = 0;

    mdnspp::observer obs{ctx,
        [&](const mdnspp::mdns_record_variant &rec, mdnspp::endpoint sender)
        {
            std::visit([&](const auto &r) {
                std::cout << sender << " -> " << r << "\n";
            }, rec);

            if (++count >= 100)
                obs.stop();
        }
    };

    obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();
}

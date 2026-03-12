#include <mdnspp/defaults.h>
#include <mdnspp/record_cache.h>

#include <thread>
#include <iostream>

// Observe mDNS traffic for 10 seconds, then insert records into a record_cache for subsequent introspection.
int main()
{
    mdnspp::context ctx;
    mdnspp::record_cache<> cache;

    mdnspp::observer obs{
        ctx,
        mdnspp::observer_options{
            .on_record = [&cache](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
            {
                cache.insert(rec, sender);
            }
        }
    };

    std::thread w([&]()
    {
        obs.async_observe();
        ctx.run();
    });
    std::this_thread::sleep_for(std::chrono::seconds(10));
    ctx.stop();
    w.join();

    auto entries = cache.snapshot();
    std::cout << "cached " << entries.size() << " record(s)\n";
    for(const auto &e : entries)
    {
        std::visit([&e](const auto &r)
        {
            std::cout << "  " << r.name << " ttl=" << e.wire_ttl << "s" << " remaining=" << std::chrono::duration_cast<std::chrono::seconds>(e.ttl_remaining).count() << "s\n";
        }, e.record);
    }
}

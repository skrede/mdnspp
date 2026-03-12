#include <mdnspp/defaults.h>
#include <mdnspp/record_cache.h>

#include <thread>
#include <iostream>

// Observe mDNS traffic, periodically evicting expired cache entries.
// Runs for 60 seconds, calling erase_expired() every second.

int main()
{
    mdnspp::context ctx;

    mdnspp::record_cache<> cache{
        {
            .on_expired = [](std::vector<mdnspp::cache_entry> expired)
            {
                for(const auto &e : expired)
                    std::visit([](const auto &r) { std::cout << "expired: " << r << std::endl; }, e.record);
            },
        }
    };

    mdnspp::observer obs{
        ctx,
        mdnspp::observer_options{
            .on_record = [&cache](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
            {
                cache.insert(rec, sender);
            }
        }
    };

    std::thread worker([&]
    {
        obs.async_observe();
        ctx.run();
    });

    for(int i = 0; i < 60; ++i)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        cache.erase_expired();
    }

    ctx.stop();
    worker.join();

    std::cout << cache.snapshot().size() << " record(s) still live" << std::endl;
}

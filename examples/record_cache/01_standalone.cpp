// Wire an observer to a standalone cache for promiscuous record collection.

#include <mdnspp/defaults.h>
#include <mdnspp/record_cache.h>

#include <csignal>
#include <iostream>

int main()
{
    mdnspp::context ctx;
    mdnspp::record_cache<> cache;

    // Wire the observer's on_record callback to cache.insert() so that every
    // received mDNS record is accumulated in the cache with its TTL.
    mdnspp::observer obs{
        ctx,
        mdnspp::observer_options{
            .on_record = [&cache](const mdnspp::endpoint &sender,
                                  const mdnspp::mdns_record_variant &rec)
            {
                cache.insert(rec, sender);
            }
        }
    };

    // Press Ctrl-C to stop the observer and inspect the accumulated cache.
    std::signal(SIGINT, [](int) {});

    obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();

    // After the event loop exits, take a snapshot and report what was cached.
    auto entries = cache.snapshot();
    std::cout << "cached " << entries.size() << " record(s)\n";
    for(const auto &e : entries)
    {
        std::visit([&e](const auto &r)
        {
            std::cout << "  " << r.name
                      << " ttl=" << e.wire_ttl << "s"
                      << " remaining=" << std::chrono::duration_cast<std::chrono::seconds>(e.ttl_remaining).count() << "s\n";
        }, e.record);
    }
}

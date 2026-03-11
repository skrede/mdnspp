// Promiscuous caching with TTL expiry notifications.

#include <mdnspp/defaults.h>
#include <mdnspp/record_cache.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    // on_expired fires with the entries that were evicted after their TTL elapsed.
    mdnspp::cache_options copts{
        .on_expired = [](std::vector<mdnspp::cache_entry> expired)
        {
            std::cout << expired.size() << " record(s) expired\n";
        },
    };

    mdnspp::record_cache<> cache{std::move(copts)};

    // Wire the observer to accumulate all received records into the cache.
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

    // Call erase_expired() periodically to evict TTL-elapsed entries and
    // trigger on_expired. Here we let the observer run until Ctrl-C.
    obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();
}

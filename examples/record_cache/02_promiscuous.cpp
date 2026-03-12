#include <mdnspp/defaults.h>
#include <mdnspp/record_cache.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::cache_options copts{
        .on_expired = [](std::vector<mdnspp::cache_entry> expired)
        {
            std::cout << expired.size() << " record(s) expired" << std::endl;
        },
    };

    mdnspp::record_cache<> cache{std::move(copts)};

    mdnspp::observer obs{
        ctx,
        mdnspp::observer_options{
            .on_record = [&cache](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
            {
                cache.insert(rec, sender);
            }
        }
    };

    obs.async_observe();
    ctx.run();
}

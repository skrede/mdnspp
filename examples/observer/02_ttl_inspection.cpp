// Enforce RFC 6762 §11 link-local filtering via receive_ttl_minimum.
//
// mDNS multicast packets must arrive with IP TTL=255 — any packet forwarded by
// a router has its TTL decremented below 255 and is therefore not link-local.
// Setting receive_ttl_minimum=255 silently discards all such forwarded packets
// before they reach the on_record callback.
//
// On platforms where IP TTL extraction is unavailable, unknown_ttl_policy
// controls whether such packets are accepted (default) or rejected.

#include <mdnspp/defaults.h>
#include <mdnspp/mdns_options.h>
#include <mdnspp/observer_options.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::mdns_options mdns_opts{
        .receive_ttl_minimum = 255,
        .unknown_ttl_policy  = mdnspp::ttl_unknown_policy::reject,
    };

    // Only packets that pass the TTL filter are delivered to on_record.
    mdnspp::observer obs{
        ctx,
        mdnspp::observer_options{
            .on_record = [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&sender](const auto &r)
                {
                    std::cout << sender << " -> " << r << std::endl;
                }, rec);
            }
        },
        mdnspp::socket_options{},
        mdns_opts
    };

    obs.async_observe([&ctx](std::error_code)
    {
        ctx.stop();
    });
    ctx.run();
}

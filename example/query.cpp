// Query for mDNS PTR records using DefaultPolicy.
// Self-terminates after 3 seconds of silence.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::querier q
    {
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

    q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr, [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
    {
        if(ec)
            std::cerr << "query error: " << ec.message() << std::endl;
        else
            std::cout << "Query complete -- " << results.size() << " record(s)" << std::endl;
        ctx.stop();
    });

    ctx.run();
}

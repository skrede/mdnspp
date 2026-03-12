#include <mdnspp/asio.h>
#include <mdnspp/records.h>
#include <mdnspp/basic_service_discovery.h>

#include <variant>
#include <iostream>

// Discover mDNS services using AsioPolicy.
// Prints each record to stdout, completes after silence timeout.

int main()
{
    asio::io_context io;
    mdnspp::basic_service_discovery<mdnspp::AsioPolicy> discovery{
        io,
        mdnspp::query_options{
            .on_record = [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&sender](const auto &r) { std::cout << sender.address << ":" << sender.port << " -> " << r << std::endl; }, rec);
            }
        }
    };

    discovery.async_discover("_http._tcp.local.", [](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
    {
        if(ec)
            std::cerr << "discovery error: " << ec.message() << std::endl;
        else
            std::cout << "Discovery complete -- " << results.size() << " record(s) " << std::endl;
    });

    io.run();
}

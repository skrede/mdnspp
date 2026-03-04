#include "mdnspp/service_discovery.h"
#include "mdnspp/asio/asio_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <asio.hpp>
#include <iostream>
#include <variant>

int main()
{
    asio::io_context io;

    mdnspp::service_discovery<mdnspp::AsioPolicy> sd{io,
        std::chrono::seconds(3),
        [](const mdnspp::mdns_record_variant &rec, mdnspp::endpoint sender)
        {
            std::visit([&sender](const auto &r)
            {
                std::cout << sender.address << ":" << sender.port
                          << " -> " << r << "\n";
            }, rec);
        }};

    sd.async_discover("_http._tcp.local.",
        [](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
            {
                std::cerr << "discovery error: " << ec.message() << "\n";
                return;
            }
            std::cout << "Discovery complete — " << results.size() << " record(s)\n";
        });

    io.run(); // blocks until silence timeout
}

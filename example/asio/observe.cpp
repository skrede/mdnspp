// Observe mDNS multicast traffic using AsioPolicy.
// Prints each record to stdout, runs until io_context work drains.
// Usage: ./mdnspp_example_asio_observe

#include <mdnspp/asio.h>
#include <mdnspp/records.h>
#include <mdnspp/basic_observer.h>

#include <variant>
#include <iostream>

int main()
{
    asio::io_context io;

    mdnspp::basic_observer<mdnspp::AsioPolicy> obs{
        io, {},
        [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&sender](const auto &r)
            {
                std::cout << sender.address << ":" << sender.port
                    << " -> " << r << "\n";
            }, rec);
        }
    };

    mdnspp::async_observe(obs, [](std::error_code)
    {
    });
    io.run();
}

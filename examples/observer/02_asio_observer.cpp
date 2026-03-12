#include <mdnspp/asio.h>
#include <mdnspp/records.h>
#include <mdnspp/basic_observer.h>

#include <variant>
#include <iostream>

// Observe mDNS multicast traffic using AsioPolicy.
// Prints each record to stdout, runs until io_context work drains.
// Usage: ./mdnspp_example_asio_observe

int main()
{
    asio::io_context io;
    mdnspp::basic_observer<mdnspp::AsioPolicy> observer{
        io,
        mdnspp::observer_options{
            .on_record = [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&sender](const auto &r)
                {
                    std::cout << sender.address << ":" << sender.port
                        << " -> " << r << std::endl;
                }, rec);
            }
        }
    };

    observer.async_observe([&io](std::error_code)
    {
        io.stop();
    });
    io.run();
}

#include "mdnspp/asio.h"
#include "mdnspp/records.h"
#include "mdnspp/basic_observer.h"

#include <asio.hpp>
#include <iostream>
#include <variant>

int main()
{
    asio::io_context io;

    mdnspp::basic_observer<mdnspp::AsioPolicy> obs{
        io,
        [](mdnspp::mdns_record_variant rec, mdnspp::endpoint sender)
        {
            std::visit([&sender](const auto &r)
            {
                std::cout << sender.address << ":" << sender.port
                    << " -> " << r << "\n";
            }, rec);
        }
    };

    obs.async_observe(); // fire-and-forget (no completion callback needed)
    io.run();
}

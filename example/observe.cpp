#include "mdnspp/observer.h"
#include "mdnspp/asio/asio_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <asio.hpp>
#include <iostream>
#include <variant>

int main()
{
    asio::io_context io;

    mdnspp::observer<mdnspp::AsioPolicy> obs{io,
        [](mdnspp::mdns_record_variant rec, mdnspp::endpoint sender)
        {
            std::visit([&sender](const auto &r)
            {
                std::cout << sender.address << ":" << sender.port
                          << " -> " << r << "\n";
            }, rec);
        }};

    obs.start();
    io.run();
}

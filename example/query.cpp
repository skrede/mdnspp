#include "mdnspp/querent.h"
#include "mdnspp/asio/asio_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <asio.hpp>
#include <iostream>
#include <string>
#include <variant>
#include <cstdint>

int main(int argc, char *argv[])
{
    std::string name = "_http._tcp.local.";
    uint16_t qtype   = 12; // PTR

    if(argc >= 2)
        name = argv[1];
    if(argc >= 3)
        qtype = static_cast<uint16_t>(std::stoi(argv[2]));

    asio::io_context io;

    mdnspp::querent<mdnspp::AsioPolicy> q{io,
        std::chrono::seconds(3),
        [](const mdnspp::mdns_record_variant &rec, mdnspp::endpoint sender)
        {
            std::visit([&sender](const auto &r)
            {
                std::cout << sender.address << ":" << sender.port
                    << " -> " << r << "\n";
            }, rec);
        }};

    q.query(name, qtype); // sends query, arms recv_loop
    io.run();             // blocks until silence timeout
}

#include "mdnspp/asio.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <iostream>
#include <string>
#include <variant>

int main(int argc, char *argv[])
{
    std::string name = "_http._tcp.local.";
    mdnspp::dns_type qtype = mdnspp::dns_type::ptr;

    if(argc >= 2)
        name = argv[1];
    if(argc >= 3)
        qtype = static_cast<mdnspp::dns_type>(std::stoi(argv[2]));

    asio::io_context io;

    mdnspp::basic_querier<mdnspp::AsioPolicy> q{
        io,
        std::chrono::seconds(3),
        [](const mdnspp::mdns_record_variant &rec, mdnspp::endpoint sender)
        {
            std::visit([&sender](const auto &r)
            {
                std::cout << sender.address << ":" << sender.port
                    << " -> " << r << "\n";
            }, rec);
        }
    };

    q.async_query(name, qtype,
                  [](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
                  {
                      if(ec)
                      {
                          std::cerr << "query error: " << ec.message() << "\n";
                          return;
                      }
                      std::cout << "Query complete — " << results.size() << " record(s)\n";
                  });

    io.run(); // blocks until silence timeout
}

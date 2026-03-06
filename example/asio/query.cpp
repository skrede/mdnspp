// Query mDNS for a specific record type using AsioPolicy.
// Prints each record to stdout, completes after silence timeout.
// Usage: ./mdnspp_example_asio_query [name] [qtype]

#include <mdnspp/asio.h>
#include <mdnspp/basic_querier.h>
#include <mdnspp/records.h>

#include <iostream>
#include <string>
#include <variant>

int main(int argc, char *argv[])
{
    std::string name = "_http._tcp.local.";
    auto qtype = mdnspp::dns_type::ptr;

    if(argc >= 2)
        name = argv[1];
    if(argc >= 3)
        qtype = static_cast<mdnspp::dns_type>(std::stoi(argv[2]));

    asio::io_context io;

    mdnspp::basic_querier<mdnspp::AsioPolicy> q{
        io,
        std::chrono::seconds(3),
        [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&sender](const auto &r)
            {
                std::cout << sender.address << ":" << sender.port
                    << " -> " << r << "\n";
            }, rec);
        }
    };

    mdnspp::async_query(q, name, qtype, [](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
    {
        if(ec)
        {
            std::cerr << "query error: " << ec.message() << "\n";
            return;
        }
        std::cout << "Query complete -- " << results.size() << " record(s)\n";
    });

    io.run();
}

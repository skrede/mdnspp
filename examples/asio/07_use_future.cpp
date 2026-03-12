#include <mdnspp/asio.h>
#include <mdnspp/records.h>
#include <mdnspp/basic_querier.h>

#include <future>
#include <thread>
#include <variant>
#include <iostream>

// Query mDNS records using asio::use_future, returning a std::future.
// The free function mdnspp::async_query() accepts any Asio completion token.

int main()
{
    asio::io_context io;
    mdnspp::basic_querier<mdnspp::AsioPolicy> querier{io};
    std::future<std::vector<mdnspp::mdns_record_variant>> fut = mdnspp::async_query(querier, "_http._tcp.local.", mdnspp::dns_type::ptr, asio::use_future);

    std::thread worker([&io]
    {
        io.run();
    });

    try
    {
        auto results = fut.get();
        std::cout << "Query complete -- " << results.size() << " record(s):" << std::endl;
        for(const auto &r : results)
            std::visit([](const auto &rec) { std::cout << "  " << rec << std::endl; }, r);
    }
    catch(const std::system_error &e)
    {
        std::cerr << "query error: " << e.what() << std::endl;
    }

    worker.join();
}

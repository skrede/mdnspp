#include <mdnspp/asio.h>
#include <mdnspp/records.h>
#include <mdnspp/basic_service_discovery.h>

#include <variant>
#include <iostream>

// Discover mDNS services using C++20 coroutines and asio::use_awaitable.
// The free function mdnspp::async_discover() accepts any Asio completion token.

asio::awaitable<void> discover(asio::io_context &io)
{
    mdnspp::basic_service_discovery<mdnspp::AsioPolicy> discovery{io};

    auto [ec, results] = co_await mdnspp::async_discover(discovery, "_http._tcp.local.", asio::as_tuple(asio::use_awaitable));

    if(ec)
    {
        std::cerr << "discovery error: " << ec.message() << std::endl;
        co_return;
    }

    std::cout << "Discovered " << results.size() << " record(s):" << std::endl;
    for(const auto &r : results)
        std::visit([](const auto &rec) { std::cout << "  " << rec << std::endl; }, r);
}

int main()
{
    asio::io_context io;
    asio::co_spawn(io, discover(io), asio::detached);
    io.run();
}

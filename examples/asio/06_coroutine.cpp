#include <mdnspp/asio.h>
#include <mdnspp/records.h>
#include <mdnspp/basic_service_discovery.h>

#include <asio/cancel_after.hpp>

#include <chrono>
#include <variant>
#include <iostream>

// Discover mDNS services using C++20 coroutines and asio::use_awaitable.
// The free function mdnspp::async_discover() accepts any Asio completion
// token. asio::cancel_after bounds the operation: when the deadline expires
// first, the discovery is cancelled through its associated cancellation slot
// and completes with std::errc::operation_canceled, carrying the records
// accumulated so far. asio::as_tuple surfaces the error_code as a value
// instead of throwing.

asio::awaitable<void> discover(asio::io_context &io)
{
    mdnspp::basic_service_discovery<mdnspp::asio_policy> discovery{io};

    auto [ec, results] = co_await mdnspp::async_discover(
        discovery, "_http._tcp.local.",
        asio::cancel_after(std::chrono::seconds(2), asio::as_tuple(asio::use_awaitable)));

    if(ec == std::errc::operation_canceled)
        std::cout << "Deadline reached -- " << results.size() << " record(s) so far:" << std::endl;
    else if(ec)
    {
        std::cerr << "discovery error: " << ec.message() << std::endl;
        co_return;
    }
    else
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

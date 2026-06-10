#include <mdnspp/asio.h>
#include <mdnspp/records.h>
#include <mdnspp/basic_observer.h>

#include <chrono>
#include <variant>
#include <iostream>

// Observe mDNS multicast traffic using asio_policy.
// Prints each record to stdout. A 30 s timer stops the observation, which
// completes the token with std::errc::operation_canceled -- the observer's
// only completion path, since an observation has no natural end.

int main()
{
    asio::io_context io;
    mdnspp::basic_observer<mdnspp::asio_policy> observer{
        io,
        mdnspp::observer_options{
            .on_record = [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&sender](const auto &r) { std::cout << sender.address << ":" << sender.port << " -> " << r << std::endl; }, rec);
            }
        }
    };

    mdnspp::async_observe(observer, [](std::error_code ec)
    {
        if(ec == std::errc::operation_canceled)
            std::cout << "Observation stopped" << std::endl;
        else if(ec)
            std::cerr << "observe error: " << ec.message() << std::endl;
    });

    asio::steady_timer stop_timer(io, std::chrono::seconds(30));
    stop_timer.async_wait([&observer](std::error_code) { observer.stop(); });

    io.run();
}

#include "mdnspp/observer.h"
#include "mdnspp/asio/asio_socket_policy.h"
#include "mdnspp/asio/asio_timer_policy.h"
#include "mdnspp/records.h"
#include "mdnspp/endpoint.h"

#include <asio.hpp>
#include <iostream>
#include <variant>

int main()
{
    asio::io_context io;

    mdnspp::asio_policy::AsioSocketPolicy socket{io};
    mdnspp::asio_policy::AsioTimerPolicy  timer{io};

    auto obs = mdnspp::observer<
        mdnspp::asio_policy::AsioSocketPolicy,
        mdnspp::asio_policy::AsioTimerPolicy>::create(
            std::move(socket),
            std::move(timer),
            [](mdnspp::mdns_record_variant rec, mdnspp::endpoint sender)
            {
                std::visit([&sender](const auto &r)
                {
                    std::cout << sender.address << ":" << sender.port
                              << " -> " << r << "\n";
                }, rec);
            });

    if (!obs.has_value())
    {
        std::cerr << "Failed to create observer\n";
        return 1;
    }

    obs->start();
    io.run();
}

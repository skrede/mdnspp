#include "mdnspp/service_discovery.h"
#include "mdnspp/asio/asio_socket_policy.h"
#include "mdnspp/asio/asio_timer_policy.h"
#include "mdnspp/records.h"

#include <asio.hpp>
#include <iostream>
#include <variant>

int main()
{
    asio::io_context io;

    mdnspp::asio_policy::AsioSocketPolicy socket{io};
    mdnspp::asio_policy::AsioTimerPolicy  timer{io};

    auto sd = mdnspp::service_discovery<
        mdnspp::asio_policy::AsioSocketPolicy,
        mdnspp::asio_policy::AsioTimerPolicy>::create(
            std::move(socket),
            std::move(timer),
            std::chrono::seconds(3));

    if (!sd.has_value())
    {
        std::cerr << "Failed to create service_discovery\n";
        return 1;
    }

    sd->discover("_http._tcp.local.");  // sends PTR query, arms recv_loop
    io.run();                            // blocks until silence timeout

    for (const auto &rec : sd->results())
    {
        std::visit([](const auto &r)
        {
            std::cout << r << "\n";
        }, rec);
    }
}

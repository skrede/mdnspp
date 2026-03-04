#include "mdnspp/querent.h"
#include "mdnspp/asio/asio_socket_policy.h"
#include "mdnspp/asio/asio_timer_policy.h"
#include "mdnspp/records.h"

#include <asio.hpp>
#include <iostream>
#include <string>
#include <variant>
#include <cstdint>

int main(int argc, char *argv[])
{
    std::string name = "_http._tcp.local.";
    uint16_t qtype = 12; // PTR

    if (argc >= 2)
        name = argv[1];
    if (argc >= 3)
        qtype = static_cast<uint16_t>(std::stoi(argv[2]));

    asio::io_context io;

    mdnspp::asio_policy::AsioSocketPolicy socket{io};
    mdnspp::asio_policy::AsioTimerPolicy  timer{io};

    auto q = mdnspp::querent<
        mdnspp::asio_policy::AsioSocketPolicy,
        mdnspp::asio_policy::AsioTimerPolicy>::create(
            std::move(socket),
            std::move(timer),
            std::chrono::seconds(3));

    if (!q.has_value())
    {
        std::cerr << "Failed to create querent\n";
        return 1;
    }

    q->query(name, qtype);     // sends query, arms recv_loop
    io.run();                   // blocks until silence timeout

    for (const auto &rec : q->results())
    {
        std::visit([](const auto &r)
        {
            std::cout << r << "\n";
        }, rec);
    }
}

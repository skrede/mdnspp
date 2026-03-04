#include "mdnspp/service_server.h"
#include "mdnspp/service_info.h"
#include "mdnspp/endpoint.h"
#include "mdnspp/asio/asio_socket_policy.h"
#include "mdnspp/asio/asio_timer_policy.h"

#include <asio.hpp>
#include <cstdint>
#include <iostream>

int main()
{
    asio::io_context io;

    mdnspp::asio_policy::AsioSocketPolicy socket{io};
    mdnspp::asio_policy::AsioTimerPolicy response_timer{io};
    mdnspp::asio_policy::AsioTimerPolicy recv_timer{io};

    mdnspp::service_info info;
    info.service_name = "MyApp._http._tcp.local.";
    info.service_type = "_http._tcp.local.";
    info.hostname     = "myhost.local.";
    info.port         = 8080;
    info.priority     = 0;
    info.weight       = 0;
    info.address_ipv4 = "192.168.1.69";
    info.txt_records  = {{"path", "/index.html"}};

    auto srv = mdnspp::service_server<
        mdnspp::asio_policy::AsioSocketPolicy,
        mdnspp::asio_policy::AsioTimerPolicy>::create(
        std::move(socket),
        std::move(response_timer),
        std::move(recv_timer),
        std::move(info),
        [](mdnspp::endpoint sender, uint16_t qtype, bool unicast)
        {
            std::cout << sender.address << ":" << sender.port
                      << " queried qtype=" << qtype
                      << (unicast ? " (unicast)" : " (multicast)") << "\n";
        });

    if (!srv.has_value())
    {
        std::cerr << "Failed to create service_server\n";
        return 1;
    }

    asio::signal_set signals(io, SIGINT);
    signals.async_wait([&srv](std::error_code, int)
    {
        srv->stop();
    });

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (Ctrl-C to stop)\n";
    srv->start();
    io.run();
}

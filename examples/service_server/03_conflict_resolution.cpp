#include <mdnspp/defaults.h>

#include <iostream>

// Demonstrates service name conflict resolution using service_options::on_conflict.
// Two servers with the same name are started simultaneously. When they detect each other's probes, the on_conflict callback renames the service and retries.

int main()
{
    mdnspp::context ctx;

    auto make_info = []()
    {
        return mdnspp::service_info{
            .service_name = "MyApp._http._tcp.local.",
            .service_type = "_http._tcp.local.",
            .hostname = "myhost.local.",
            .port = 8080,
            .address_ipv4 = "192.168.1.69",
            .address_ipv6 = {},
            .txt_records = {{"path", "/spandex.html"}},
            .subtypes = {},
        };
    };

    auto make_opts = [](const std::string &label)
    {
        mdnspp::service_options opts;
        opts.on_conflict = [label](const std::string &conflicting_name,
                                   std::string &new_name,
                                   unsigned attempt) -> bool
        {
            if(attempt >= 3)
                return false;

            new_name = conflicting_name;
            auto pos = new_name.find("._http");
            if(pos != std::string::npos)
                new_name.insert(pos, " (" + std::to_string(attempt + 1) + ")");

            std::cout << "[" << label << "] Conflict on \"" << conflicting_name
                << "\", retrying as \"" << new_name << "\"" << std::endl;
            return true;
        };
        return opts;
    };

    mdnspp::socket_options sock_opts;
    sock_opts.multicast_loopback = mdnspp::loopback_mode::enabled;

    mdnspp::service_server srv_a{ctx, make_info(), make_opts("A"), sock_opts};
    mdnspp::service_server srv_b{ctx, make_info(), make_opts("B"), sock_opts};

    int ready_count = 0;
    auto on_ready = [&](const std::string &label)
    {
        return [&, label](std::error_code ec)
        {
            if(ec)
                std::cerr << "[" << label << "] Failed: " << ec.message() << std::endl;
            else
                std::cout << "[" << label << "] Service is live" << std::endl;

            if(++ready_count == 2)
                ctx.stop();
        };
    };

    srv_a.async_start(on_ready("A"));
    srv_b.async_start(on_ready("B"));

    ctx.run();
}

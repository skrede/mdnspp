// Demonstrates service name conflict resolution using service_options::on_conflict.
// When another device on the network claims the same name, the on_conflict callback
// renames the service and retries probing up to 3 times.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.69",
        .address_ipv6 = {},
        .txt_records  = {{"path", "/index.html"}},
        .subtypes     = {},
    };

    mdnspp::service_options opts;
    opts.on_conflict = [](const std::string &conflicting_name,
                          std::string &new_name,
                          unsigned attempt) -> bool
    {
        if(attempt >= 3)
            return false; // give up after 3 retries

        new_name = conflicting_name;
        // Insert attempt number before the service type suffix
        auto pos = new_name.find("._http");
        if(pos != std::string::npos)
            new_name.insert(pos, " (" + std::to_string(attempt + 1) + ")");

        std::cout << "Conflict on \"" << conflicting_name
                  << "\", retrying as \"" << new_name << "\"\n";
        return true;
    };

    mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};

    srv.async_start(
        [](std::error_code ec)
        {
            if(ec)
                std::cerr << "Server failed: " << ec.message() << "\n";
            else
                std::cout << "Service is live\n";
        },
        [&ctx](std::error_code)
        {
            ctx.stop();
        });

    ctx.run();
}

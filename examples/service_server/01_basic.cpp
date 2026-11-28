#include <mdnspp/defaults.h>

#include <thread>
#include <iostream>

// Announce an HTTP service via mDNS using default_policy.
//
// service_info::make() derives the full record set from an instance label and
// a service type: the hostname comes from the OS, ".local." is appended to
// the bare type, and the A/AAAA addresses are resolved from the announcing
// interface at async_start. Auto-stops after 30 seconds.

int main()
{
    mdnspp::context ctx;

    auto info = mdnspp::service_info::make(
        "MyApp", "_http._tcp", 8080,
        {.txt_records = {{"path", "/index.html"}}});
    if(!info.has_value())
    {
        std::cerr << "service_info::make failed: "
                  << make_error_code(info.error()).message() << std::endl;
        return 1;
    }

    mdnspp::service_server srv{
        ctx,
        std::move(*info),
        mdnspp::service_options{
            .on_query = [](const mdnspp::endpoint &sender, mdnspp::dns_type qtype, mdnspp::response_mode mode)
            {
                std::cout << sender << " queried qtype=" << to_string(qtype) << " (" << to_string(mode) << ")" << std::endl;
            }
        }
    };

    std::thread shutdown([&ctx]
    {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        ctx.stop();
    });

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (30s then auto-stop)" << std::endl;
    srv.async_start();
    ctx.run();

    shutdown.join();
}

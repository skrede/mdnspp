// Discovers all service types on the local network using DNS-SD service type
// enumeration (RFC 6763 section 9). Queries _services._dns-sd._udp.local. and
// prints each discovered type's components.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{ctx, std::chrono::seconds(3)};

    sd.async_enumerate_types(
        [&ctx](std::error_code ec, std::vector<mdnspp::service_type_info> types)
        {
            if(ec)
            {
                std::cerr << "Enumeration error: " << ec.message() << std::endl;
                ctx.stop();
                return;
            }

            std::cout << "Found " << types.size() << " service type(s):" << std::endl;
            for(const auto &t : types)
                std::cout << "  " << t.type_name << "." << t.protocol
                    << "." << t.domain << std::endl;

            ctx.stop();
        });

    ctx.run();
}

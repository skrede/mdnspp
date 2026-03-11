# Getting Started

## Prerequisites

- C++23 compiler: GCC 13+, Clang 18+, MSVC 17+, or Xcode 15.4+
- CMake 3.25+

## Installation

### FetchContent (recommended)

```cmake
include(FetchContent)
FetchContent_Declare(
    mdnspp
    GIT_REPOSITORY https://github.com/skrede/mdnspp.git
    GIT_TAG        master
)
FetchContent_MakeAvailable(mdnspp)

target_link_libraries(my_app PRIVATE mdnspp::mdnspp)
```

This pulls mdnspp and links the DefaultPolicy target, which provides native
socket and timer implementations with no external dependencies.

### find_package

```cmake
find_package(mdnspp CONFIG REQUIRED)
target_link_libraries(my_app PRIVATE mdnspp::mdnspp)
```

See [CMake Integration](cmake-integration.md) for installation instructions and
all available targets.

## Discover services on your network

The following program discovers `_http._tcp.local.` services on the local
network and prints each DNS record as it arrives. Discovery completes after
3 seconds of silence (no new records).

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{ctx,
        mdnspp::query_options{
            .on_record = [](const mdnspp::endpoint &sender,
                            const mdnspp::mdns_record_variant &rec)
            {
                std::visit([&](const auto &r) {
                    std::cout << sender << " -> " << r << "\n";
                }, rec);
            }
        }
    };

    sd.async_discover("_http._tcp.local.",
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
                std::cerr << "discovery error: " << ec.message() << "\n";
            else
                std::cout << "discovered " << results.size() << " record(s)\n";
            ctx.stop(); // ctx.stop() ends ctx.run()
        });

    ctx.run();
}
```

`mdnspp::context` is the event loop. `ctx.run()` blocks until `ctx.stop()` is
called -- without that call in the completion callback, the program hangs.

The `query_options` struct holds a per-record callback (invoked as records
arrive) and a silence timeout (default 3 seconds). The lambda passed to
`async_discover` is the completion callback, invoked once when discovery
finishes (silence timeout or error).

For resolved service instances (hostname, port, addresses) instead of raw
records, use `async_browse` -- it returns `std::vector<resolved_service>`
directly. For service type enumeration and subtype discovery, see
[service_discovery](api/service_discovery.md).

## Announce a service

The following program announces an HTTP service on port 8080 via mDNS and
responds to queries for 30 seconds.

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <iostream>
#include <thread>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.69",
        .txt_records  = {{"path", "/index.html"}},
    };

    mdnspp::service_server srv{ctx, std::move(info)};

    std::thread shutdown{[&ctx] {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        ctx.stop(); // ctx.stop() ends ctx.run()
    }};

    srv.async_start();
    ctx.run();

    shutdown.join();
}
```

`service_info` uses designated initializers to describe the service. The
server begins responding to mDNS queries after `async_start()` is called.
A background thread stops the context after 30 seconds; in a real application,
you would tie the stop to your own shutdown signal.

Multiple mdnspp components can share the same context -- for example, two
`service_server` instances or a `service_server` and an `observer` on one
event loop. Each component creates its own socket, and the context
multiplexes them all. See the `multi_serve` example.

For conflict resolution, goodbye packets, and other server options, see
[service_options](api/service_options.md). For RFC compliance details, see
[RFC Compliance](rfc/README.md).

## What's next

- [Service Options](api/service_options.md) -- conflict resolution, goodbye, announcement tuning
- [RFC Compliance](rfc/README.md) -- RFC 6762/6763 conformance status and feature documentation
- [Policies](policies.md) -- understand the DefaultPolicy, AsioPolicy, and MockPolicy architecture
- [Async Patterns](async-patterns.md) -- use ASIO completion tokens (futures, coroutines, deferred)
- [API Reference](api/) -- full type documentation

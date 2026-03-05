# mdnspp

[![Linux](https://github.com/skrede/mdnspp/actions/workflows/linux.yml/badge.svg?branch=master)](https://github.com/skrede/mdnspp/actions/workflows/linux.yml)
[![macOS](https://github.com/skrede/mdnspp/actions/workflows/macos.yml/badge.svg?branch=master)](https://github.com/skrede/mdnspp/actions/workflows/macos.yml)
[![Windows](https://github.com/skrede/mdnspp/actions/workflows/windows.yml/badge.svg?branch=master)](https://github.com/skrede/mdnspp/actions/workflows/windows.yml)
[![codecov](https://codecov.io/gh/skrede/mdnspp/branch/master/graph/badge.svg)](https://codecov.io/gh/skrede/mdnspp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)

A C++23 mDNS/DNS-SD library with a policy-based architecture. mdnspp is fully standalone -- no Boost dependency, no hidden threads, no owned allocations. The policy design lets it compose naturally with any executor or event loop: use the built-in native sockets for standalone applications, or plug in ASIO for completion token support. Cross-platform on Linux, macOS, and Windows.

## Features

- **Standalone native networking** -- no external dependencies for the default policy
- **Policy-based architecture** -- swap socket/timer/executor implementations at compile time
- **ASIO completion token support** -- callbacks, futures, coroutines, and deferred operations
- **Cross-platform** -- Linux, macOS, and Windows
- **Type-safe DNS enums** -- `dns_type`, `dns_class` as scoped enums
- **Service discovery with record aggregation** -- raw records or fully resolved services

## Quick Start

### Observe mDNS Traffic

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;

    mdnspp::observer obs{ctx,
        [&](const mdnspp::mdns_record_variant &rec, mdnspp::endpoint sender)
        {
            std::visit([&](const auto &r) {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    obs.async_observe([&ctx](std::error_code) { ctx.stop(); }); // ctx.stop() ends ctx.run()
    ctx.run();
}
```

### Query for Records

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;

    mdnspp::querier q{ctx, std::chrono::seconds(3),
        [](const mdnspp::mdns_record_variant &rec, mdnspp::endpoint sender)
        {
            std::visit([&](const auto &r) {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
                std::cerr << "query error: " << ec.message() << "\n";
            else
                std::cout << results.size() << " record(s)\n";
            ctx.stop(); // ctx.stop() ends ctx.run()
        });

    ctx.run();
}
```

### Discover Services

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/records.h>

#include <iostream>
#include <variant>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{ctx, std::chrono::seconds(3),
        [](const mdnspp::mdns_record_variant &rec, mdnspp::endpoint sender)
        {
            std::visit([&](const auto &r) {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    sd.async_discover("_http._tcp.local.",
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
                std::cerr << "discovery error: " << ec.message() << "\n";
            else
                std::cout << results.size() << " record(s)\n";
            ctx.stop(); // ctx.stop() ends ctx.run()
        });

    ctx.run();
}
```

### Announce a Service

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

    std::jthread shutdown{[&ctx](std::stop_token) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        ctx.stop(); // ctx.stop() ends ctx.run()
    }};

    srv.async_start();
    ctx.run();
}
```

## CMake Integration

The quickest way to add mdnspp to your project is with FetchContent:

```cmake
include(FetchContent)
FetchContent_Declare(
    mdnspp
    GIT_REPOSITORY https://github.com/skrede/mdnspp.git
    GIT_TAG        master  # pin to a specific commit for reproducibility
)
FetchContent_MakeAvailable(mdnspp)

target_link_libraries(my_app PRIVATE mdnspp::native)
# or: target_link_libraries(my_app PRIVATE mdnspp::asio)
```

For `find_package`, building from source, and all available CMake targets, see the [CMake Integration](doc/cmake-integration.md) guide.

## Documentation

- [Getting Started](doc/getting-started.md) -- Install mdnspp and run your first query or service announcement
- [Policies](doc/policies.md) -- Understand DefaultPolicy, AsioPolicy, and MockPolicy
- [Async Patterns](doc/async-patterns.md) -- ASIO completion tokens: callbacks, futures, coroutines, deferred
- [CMake Integration](doc/cmake-integration.md) -- FetchContent, find_package, and building from source
- [API Reference](doc/api/)

## License

MIT License -- see [LICENSE](LICENSE) for details.

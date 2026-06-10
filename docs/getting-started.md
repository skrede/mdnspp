# Getting Started

## Prerequisites

- C++20 compiler: GCC 13+, Clang 17+, MSVC 19.34+ (Visual Studio 2022), or Xcode 15.4+
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

This pulls mdnspp and links the default_policy target, which provides native
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
                    std::cout << sender << " -> " << r << std::endl;
                }, rec);
            }
        }
    };

    sd.async_discover("_http._tcp.local.",
        [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
        {
            if (ec)
                std::cerr << "discovery error: " << ec.message() << std::endl;
            else
                std::cout << "discovered " << results.size() << " record(s)" << std::endl;
            ctx.stop(); // ctx.stop() ends ctx.run()
        });

    ctx.run();
}
```

`mdnspp::context` is the event loop. `ctx.run()` blocks until `ctx.stop()` is
called &mdash; without that call in the completion callback, the program hangs.

The `query_options` struct holds a per-record callback (invoked as records
arrive) and a silence timeout (default 3 seconds). The lambda passed to
`async_discover` is the completion callback, invoked once when discovery
finishes (silence timeout or error).

For resolved service instances (hostname, port, addresses) instead of raw
records, use `async_browse` &mdash; it returns `std::vector<resolved_service>`
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

    auto info = mdnspp::service_info::make("MyApp", "_http._tcp", 8080,
                                           {.txt_records = {{"path", "/index.html"}}});
    if(!info.has_value())
    {
        std::cerr << "invalid service description: "
                  << make_error_code(info.error()).message() << std::endl;
        return 1;
    }

    mdnspp::service_server srv{ctx, std::move(*info)};

    std::thread shutdown{[&srv] {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        srv.stop(); // safe from any thread; goodbye is sent on the executor
    }};

    srv.async_start(
        [](std::error_code ec)
        {
            if (ec)
                std::cerr << "start failed: " << ec.message() << std::endl;
            else
                std::cout << "service is live" << std::endl;
        },
        [&ctx](std::error_code)
        {
            ctx.stop(); // teardown complete (goodbye sent); ends ctx.run()
        });
    ctx.run();

    shutdown.join();
}
```

`service_info::make()` returns `expected<service_info, mdns_error>`: it
validates the service type (`mdns_error::invalid_name`) and the port
(`mdns_error::invalid_argument`), escapes the instance label per
RFC 1035 §5.1, appends `".local."` to a bare type, derives the hostname from
the OS host name, and marks the unset A/AAAA addresses for resolution from
the announcing interface at `async_start` (RFC 6762 §6.2). Every field can
instead be specified explicitly with an aggregate-initialized `service_info`
using designated initializers — addresses are then announced exactly as
given, and unset fields are omitted (see
[service_info](api/service_info.md)). The server probes for name uniqueness,
announces, and then responds to mDNS queries. `async_start` takes two handlers: `on_ready` fires once with the
startup outcome (`std::error_code{}` when live, `mdns_error::probe_conflict`
when another responder holds the name and no `on_conflict` rename is
provided), and `on_done` always fires after teardown completes. A background
thread stops the server after 30 seconds; in a real application, you would
tie the stop to your own shutdown signal.

Multiple mdnspp components can share the same context &mdash; for example, two
`service_server` instances or a `service_server` and an `observer` on one
event loop. Each component creates its own socket, and the context
multiplexes them all. See the `multi_serve` example.

For conflict resolution, goodbye packets, and other server options, see
[service_options](api/service_options.md). For RFC compliance details, see
[RFC Compliance](rfc/README.md).

## Multi-interface scenarios

When a host has multiple network interfaces and you need mDNS to operate on
all of them simultaneously, `nic_group` provides automatic NIC management.
It starts one set of peer instances (monitors, servers, or observers) per
active interface and keeps them synchronized as interfaces are added or
removed at runtime:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/monitor_options.h>

#include <vector>
#include <iostream>

mdnspp::context ctx;

// Event callbacks are group-level and fire once per interface, with the
// originating network_interface passed as the leading parameter.
mdnspp::nic_group_options grp_opts{
    .on_found = [](const mdnspp::network_interface &nic,
                   const mdnspp::resolved_service &svc)
    {
        std::cout << svc.instance_name << " on " << nic.name << std::endl;
    },
};

// Per-NIC options carry tuning only — monitor_options is move-only, so
// build the vector with push_back rather than an initializer list.
std::vector<mdnspp::monitor_options> opts_vec;
opts_vec.push_back(mdnspp::monitor_options{});

mdnspp::nic_group<mdnspp::basic_service_monitor> grp{
    ctx,
    std::move(grp_opts),
    std::move(opts_vec)
};

grp.watch("_http._tcp.local.");
grp.start();
ctx.run();
```

Per-NIC `monitor_options` and `observer_options` elements must not carry
callbacks — the group rejects them; register event callbacks on
`nic_group_options` instead.

See the [NIC Group guide](nic-group.md) for monitor-only, announce+monitor,
dynamic builder, dedup modes, and interface filtering patterns.

## What's next

- [Service Options](api/service_options.md) &mdash; conflict resolution, goodbye, announcement tuning
- [RFC Compliance](rfc/README.md) &mdash; RFC 6762/6763 conformance status and feature documentation
- [Policies](policies.md) &mdash; understand the default_policy, asio_policy, and mock_policy architecture
- [Async Patterns](async-patterns.md) &mdash; use ASIO completion tokens (futures, coroutines, deferred)
- [NIC Group](nic-group.md) &mdash; multi-NIC orchestration guide
- [API Reference](api/) &mdash; full type documentation

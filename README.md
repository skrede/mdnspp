# mDNSpp

[![Linux](https://github.com/skrede/mdnspp/actions/workflows/linux.yml/badge.svg?branch=master)](https://github.com/skrede/mdnspp/actions/workflows/linux.yml)
[![macOS](https://github.com/skrede/mdnspp/actions/workflows/macos.yml/badge.svg?branch=master)](https://github.com/skrede/mdnspp/actions/workflows/macos.yml)
[![Windows](https://github.com/skrede/mdnspp/actions/workflows/windows.yml/badge.svg?branch=master)](https://github.com/skrede/mdnspp/actions/workflows/windows.yml)
[![codecov](https://codecov.io/gh/skrede/mdnspp/branch/master/graph/badge.svg)](https://codecov.io/gh/skrede/mdnspp)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://en.cppreference.com/w/cpp/23)

**mdnspp** is a C++23 mDNS/DNS-SD library with a policy-based architecture. The library is fully standalone -- no Boost dependency and no hidden threads. The policy design lets it compose naturally with any executor or event loop: use the built-in native sockets for standalone applications, or plug in ASIO for completion token support. Cross-platform on Linux, macOS, and Windows.

## Features

- **Cross-platform** -- Linux, macOS, and Windows.
- **Standalone native networking** -- no external dependencies for the default policy.
- **Network interface selection** -- run mDNS services on any NIC or bind to a specific NIC.
- **Thread-safe service updates** -- safely modify the records of running mDNS service server from any thread.
- **Policy-based architecture** -- swap socket/timer/executor implementations at compile time.
- **Optional ASIO support** -- networking and completion token support (callbacks, futures, coroutines, and deferred operations).
- **RFC 6762/6763 compliance** -- probing, goodbye packets, known-answer suppression, traffic reduction, and [DNS-SD](doc/rfc/README.md).

## Quick Start

This section presents a short mDNS primer and short examples on how to use mdnspp. The examples show how to announce a service, discover the service, how to query for the service, and the observer that observes all this traffic.

### mDNS primer

mDNS (Multicast DNS) lets devices discover each other on a local network without a central DNS server. Every device joins a multicast group and can both ask and answer questions using the `.local.` domain — for example, resolving `printer.local.` to an IP address.

DNS-SD (DNS Service Discovery) builds on top of mDNS to advertise and find *services*. A service type like `_http._tcp.local.` groups all HTTP servers on the network; each one publishes a set of DNS records (PTR, SRV, A/AAAA, TXT) that tell browsers where to connect and what options are available.

The main record types you will encounter:

| Record | Purpose |
|--------|---------|
| **PTR** | Maps a service type to one or more named instances |
| **SRV** | Gives the hostname and port for a specific instance |
| **A / AAAA** | Resolves a hostname to an IPv4 / IPv6 address |
| **TXT** | Carries key-value metadata for a service instance |

A typical discovery flow looks like this: query for PTR records of a service type → follow each PTR to its SRV → resolve the SRV hostname via A/AAAA → optionally read TXT metadata.


### Announce a Service

```cpp
#include <mdnspp/defaults.h>

#include <thread>
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
    };

    mdnspp::service_server srv{ctx, std::move(info)};

    srv.async_start(
        [](std::error_code ec)
        {
            if(ec)
                std::cerr << "Start failed: " << ec.message() << "\n";
            else
                std::cout << "Service is live\n";
        },
        [&ctx](std::error_code)
        {
            ctx.stop();
        });

    std::thread shutdown([&srv]
    {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        srv.stop();
    });

    std::cout << "Serving MyApp._http._tcp.local. on port 8080 (30s then auto-stop)\n";
    ctx.run();

    shutdown.join();
}
```

```console
[mdnspp@dev ~]$ ./serve
Serving MyApp._http._tcp.local. on port 8080 (30s then auto-stop)
Service is live
```

### Discover Services

```cpp
// Discover HTTP services on the local network using DefaultPolicy.
// Self-terminates after 3 seconds of silence.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_discovery sd{
        ctx,
        std::chrono::seconds(3), {},
        [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&](const auto &r)
            {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    sd.async_discover("_http._tcp.local.",
    [&ctx](std::error_code ec, const std::vector<mdnspp::mdns_record_variant> &results)
    {
        if(ec)
            std::cerr << "Discovery error: " << ec.message() << "\n";
        else
            std::cout << "Discovery complete: " << results.size() << " record(s)\n";
        ctx.stop();
    });

    ctx.run();
}
```

```console
[mdnspp@dev ~]$ ./discover
192.168.1.67:5353 -> 192.168.1.67: PTR _http._tcp.local -> MyApp._http._tcp.local rclass IN ttl 4500 length 24
192.168.1.67:5353 -> 192.168.1.67: SRV MyApp._http._tcp.local -> myhost.local port 8080 weight 0 priority 0 rclass IN ttl 4500 length 20
192.168.1.67:5353 -> 192.168.1.67: A myhost.local -> 192.168.1.67 rclass IN ttl 4500 length 4
192.168.1.67:5353 -> 192.168.1.67: TXT MyApp._http._tcp.local path=/index.html rclass IN ttl 4500 length 17
Discovery complete: 4 record(s)
```

### Query for Records

```cpp
// Query for mDNS PTR records using DefaultPolicy.
// Self-terminates after 3 seconds of silence.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::querier q
    {
        ctx,
        std::chrono::seconds(3), {},
        [](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&](const auto &r)
            {
                std::cout << sender << " -> " << r << "\n";
            }, rec);
        }
    };

    q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
    [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
    {
        if(ec)
            std::cerr << "query error: " << ec.message() << "\n";
        else
            std::cout << "Query complete -- " << results.size() << " record(s)\n";
        ctx.stop();
    });

    ctx.run();
}
```

```console
[mdnspp@dev ~]$ ./query
192.168.1.67:5353 -> 192.168.1.67: PTR _http._tcp.local -> MyApp._http._tcp.local rclass IN ttl 4500 length 24
192.168.1.67:5353 -> 192.168.1.67: SRV MyApp._http._tcp.local -> myhost.local port 8080 weight 0 priority 0 rclass IN ttl 4500 length 20
192.168.1.67:5353 -> 192.168.1.67: A myhost.local -> 192.168.1.67 rclass IN ttl 4500 length 4
192.168.1.67:5353 -> 192.168.1.67: TXT MyApp._http._tcp.local path=/index.html rclass IN ttl 4500 length 17
Query complete -- 4 record(s)
```

### Observe mDNS Traffic

```cpp
// Observe mDNS multicast traffic using DefaultPolicy.
// Prints each record to stdout, stops after 10 records.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;
    int count = 0;

    mdnspp::observer obs
    {
        ctx, {},
        [&](const mdnspp::endpoint &sender, const mdnspp::mdns_record_variant &rec)
        {
            std::visit([&](const auto &r)
            {
                std::cout << sender << " -> " << r << "\n";
            }, rec);

            if(++count >= 10)
                obs.stop();
        }
    };

    obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();
}
```

```console
[mdnspp@dev ~]$ ./observe
192.168.1.67:5353 -> 192.168.1.67: PTR _http._tcp.local -> MyApp._http._tcp.local rclass IN ttl 4500 length 24
192.168.1.67:5353 -> 192.168.1.67: SRV MyApp._http._tcp.local -> myhost.local port 8080 weight 0 priority 0 rclass IN ttl 4500 length 20
192.168.1.67:5353 -> 192.168.1.67: A myhost.local -> 192.168.1.67 rclass IN ttl 4500 length 4
192.168.1.67:5353 -> 192.168.1.67: TXT MyApp._http._tcp.local path=/index.html rclass IN ttl 4500 length 17
192.168.1.67:5353 -> 192.168.1.67: PTR _http._tcp.local -> MyApp._http._tcp.local rclass IN ttl 4500 length 24
192.168.1.67:5353 -> 192.168.1.67: SRV MyApp._http._tcp.local -> myhost.local port 8080 weight 0 priority 0 rclass IN ttl 4500 length 20
192.168.1.67:5353 -> 192.168.1.67: A myhost.local -> 192.168.1.67 rclass IN ttl 4500 length 4
192.168.1.67:5353 -> 192.168.1.67: TXT MyApp._http._tcp.local path=/index.html rclass IN ttl 4500 length 17
```

### Unicast responses (QU bit)

All mDNS traffic is multicast by default -- every device on the network sees every response.
However, a querier can set the QU bit (RFC 6762 §5.4) to request a unicast reply sent directly back to it, skipping the multicast group entirely.
This can be useful when a device first joins the network and wants a fast answer without waiting for the usual multicast delay.

On the client side, pass `response_mode::unicast` to `async_query`, `async_discover`, or `async_browse` to set the QU bit in the outgoing query:

```cpp
q.async_query("_http._tcp.local.", mdnspp::dns_type::ptr,
    [&ctx](std::error_code ec, std::vector<mdnspp::mdns_record_variant> results)
    {
        std::cout << results.size() << " record(s)\n";
        ctx.stop();
    },
    mdnspp::response_mode::unicast);
```

On the server side, `service_server` detects the QU bit automatically and routes the response accordingly.
To log incoming queries, set `service_options::on_query` -- `service_server` handles responses internally:

```cpp
mdnspp::service_options opts;
opts.on_query = [](const mdnspp::endpoint &sender,
                   mdnspp::dns_type qtype,
                   mdnspp::response_mode mode)
{
    std::cout << sender << " queried qtype=" << to_string(qtype)
              << " (" << to_string(mode) << ")\n";
};

mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};
```

```console
[mdnspp@dev ~]$ ./serve
Serving MyApp._http._tcp.local. on port 8080 (30s then auto-stop)
Service is live
192.168.1.67:5353 queried qtype=PTR (multicast)
192.168.1.42:5353 queried qtype=SRV (unicast)
```

### Enumerate Service Types

DNS-SD defines a meta-query that discovers all service types advertised on the local network.
`async_enumerate_types` sends this query and returns parsed `service_type_info` values:

```cpp
mdnspp::service_discovery sd{ctx, std::chrono::seconds(3)};

sd.async_enumerate_types(
    [&ctx](std::error_code ec, std::vector<mdnspp::service_type_info> types)
    {
        for(const auto &t : types)
            std::cout << t.type_name << "." << t.protocol << "." << t.domain << "\n";
        ctx.stop();
    });

ctx.run();
```

```console
[mdnspp@dev ~]$ ./enumerate
_http._tcp.local
_ssh._tcp.local
_ipp._tcp.local
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

target_link_libraries(my_app PRIVATE mdnspp::mdnspp)
# or: target_link_libraries(my_app PRIVATE mdnspp::asio)
```

For `find_package`, building from source, and all available CMake targets, see the [CMake Integration](doc/cmake-integration.md) guide.

## Documentation

- [Getting Started](doc/getting-started.md) -- Install mdnspp and run your first query or service announcement
- [Policies](doc/policies.md) -- Understand DefaultPolicy, AsioPolicy, and MockPolicy
- [Socket Options](doc/socket-options.md) -- Network interface selection, multicast TTL, and loopback control
- [Async Patterns](doc/async-patterns.md) -- ASIO completion tokens: callbacks, futures, coroutines, deferred
- [CMake Integration](doc/cmake-integration.md) -- FetchContent, find_package, and building from source
- [Service Options](doc/api/service_options.md) -- Conflict resolution, goodbye, announcement tuning
- [RFC Compliance](doc/rfc/README.md) -- RFC 6762/6763 conformance status and feature documentation
- [API Reference](doc/api/)

## License

MIT License -- see [LICENSE](LICENSE) for details.

# mdnspp Documentation

Guides and API reference for the mdnspp C++23 mDNS/DNS-SD library.

## Guides

- [Getting Started](getting-started.md) -- Install mdnspp and run your first query or service announcement
- [Policies](policies.md) -- Understand DefaultPolicy, AsioPolicy, and MockPolicy
- [Socket Options](socket-options.md) -- Network interface selection, multicast TTL, and loopback control
- [Async Patterns](async-patterns.md) -- ASIO completion tokens: callbacks, futures, coroutines, deferred
- [CMake Integration](cmake-integration.md) -- FetchContent, find_package, and building from source

## API Reference

- [observer](api/observer.md) -- mDNS multicast listener
- [querier](api/querier.md) -- mDNS query client
- [service_discovery](api/service_discovery.md) -- mDNS service browser with record aggregation
- [service_server](api/service_server.md) -- mDNS service responder
- [resolved_service](api/resolved_service.md) -- Aggregated service result from discovery

# mdnspp Documentation

Guides and API reference for the mdnspp C++23 mDNS/DNS-SD library.

## Getting Started

- [Getting Started](getting-started.md) -- Install mdnspp and run your first query or service announcement

## Guides

- [Policies](policies.md) -- Understand DefaultPolicy, AsioPolicy, and MockPolicy
- [Socket Options](socket-options.md) -- Network interface selection, multicast TTL, and loopback control
- [Async Patterns](async-patterns.md) -- ASIO completion tokens: callbacks, futures, coroutines, deferred
- [CMake Integration](cmake-integration.md) -- FetchContent, find_package, and building from source
- [Service Monitor](service-monitor.md) -- Continuous service tracking: monitoring modes, TTL refresh, loss detection
- [Record Cache](record-cache.md) -- Standalone TTL-aware record cache: standalone vs wired usage, cache-flush semantics
- [mDNS Options](mdns-options.md) -- Protocol timing tunables: query backoff, TTL refresh thresholds, TC handling
- [Custom Policies](custom-policies.md) -- Writing your own Policy, SocketLike, and TimerLike implementations

## API Reference

### Core Types

- [resolved_service](api/resolved_service.md) -- Aggregated service result from discovery or monitoring

### Observers and Queriers

- [observer](api/observer.md) -- mDNS multicast listener
- [observer_options](api/observer_options.md) -- Observer callback configuration
- [querier](api/querier.md) -- mDNS query client
- [query_options](api/query_options.md) -- Querier/discovery callback and timeout configuration

### Service Discovery

- [service_discovery](api/service_discovery.md) -- One-shot mDNS service browser with record aggregation
- [service_monitor](api/service_monitor.md) -- Continuous mDNS service tracker with TTL refresh and loss detection
- [monitor_options](api/monitor_options.md) -- Service monitor lifecycle callbacks and monitoring mode

### Service Announcement

- [service_server](api/service_server.md) -- mDNS service responder
- [service_options](api/service_options.md) -- Service announcement configuration

### Cache

- [record_cache](api/record_cache.md) -- Standalone TTL-aware record cache
- [cache_options](api/cache_options.md) -- Record cache expiry and cache-flush callbacks
- [cache_entry](api/cache_entry.md) -- Cached mDNS record snapshot with TTL information

### Configuration

- [mdns_options](api/mdns_options.md) -- Protocol timing tunables: query backoff, TTL refresh, TC handling

## RFC Compliance

- [RFC Compliance](rfc/README.md) -- RFC 6762/6763 conformance status and feature documentation
  - [Query Backoff](rfc/query-backoff.md) -- RFC 6762 §5.2 exponential backoff for continuous querying
  - [TC Handling](rfc/tc-handling.md) -- RFC 6762 §6 truncated-response accumulation
  - [Known-Answer Suppression](rfc/known-answer-suppression.md) -- RFC 6762 §7.1 known-answer lists
  - [Duplicate Suppression](rfc/duplicate-suppression.md) -- RFC 6762 §7.4 duplicate answer suppression
  - [Cache Flush](rfc/cache-flush.md) -- RFC 6762 §10.2 cache-flush semantics
  - [Goodbye](rfc/goodbye.md) -- RFC 6762 §11.3 goodbye packet handling
  - [Probing](rfc/probing.md) -- RFC 6762 §8 name uniqueness probing
  - [DNS-SD](rfc/dns-sd.md) -- RFC 6763 DNS-SD service discovery
  - [Traffic Reduction](rfc/traffic-reduction.md) -- RFC 6762 §11 traffic reduction techniques

## Examples

- [examples/observer/](../examples/observer/) -- Passive mDNS traffic observation
- [examples/querier/](../examples/querier/) -- Sending mDNS queries
- [examples/service_discovery/](../examples/service_discovery/) -- One-shot service browsing
- [examples/service_server/](../examples/service_server/) -- Announcing services
- [examples/service_monitor/](../examples/service_monitor/) -- Continuous service monitoring (basic, custom group, observe mode)
- [examples/record_cache/](../examples/record_cache/) -- Standalone and wired cache usage
- [examples/asio/](../examples/asio/) -- ASIO completion token variants (callbacks, coroutines, futures)

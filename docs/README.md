# mdnspp Documentation

Guides and API reference for the mdnspp C++23 mDNS/DNS-SD library.

## Getting Started

- [Getting Started](getting-started.md) &mdash; Install mdnspp and run your first query or service announcement

## Guides

- [Policies](policies.md) &mdash; Understand DefaultPolicy, AsioPolicy, and MockPolicy
- [Socket Options](socket-options.md) &mdash; Network interface selection, multicast TTL, and loopback control
- [Async Patterns](async-patterns.md) &mdash; ASIO completion tokens: callbacks, futures, coroutines, deferred
- [CMake Integration](cmake-integration.md) &mdash; FetchContent, find_package, and building from source
- [Service Monitor](service-monitor.md) &mdash; Continuous service tracking: monitoring modes, TTL refresh, loss detection
- [Record Cache](record-cache.md) &mdash; Standalone TTL-aware record cache: standalone vs wired usage, cache-flush semantics
- [mDNS Options](mdns-options.md) &mdash; Protocol timing tunables: query backoff, TTL refresh thresholds, TC handling
- [Custom Policies](custom-policies.md) &mdash; Writing your own Policy, SocketLike, and TimerLike implementations
- [In-Process Bus](inproc-bus.md) &mdash; InProcPolicy and shared bus for in-process mDNS scenarios
- [Test Landscape](testing.md) -- Unit, integration, fuzz, and compile test categories
- [NIC Group](nic-group.md) -- Multi-NIC orchestration: basic_nic_group, basic_nic_monitor, dynamic_nic_group

## Encrypted mDNS

- [Encrypted mDNS](encrypt/README.md) -- PSK-based encryption for mDNS multicast traffic (not RFC-defined)
  - [Encrypted mDNS Guide](encrypt/encrypted-mdns.md) -- PSK setup, key rotation, auth-only mode, convenience aliases
  - [Key Rotation](encrypt/key-rotation.md) -- Epoch-based dual-key overlap and grace period semantics
  - [Auth-Only Mode](encrypt/auth-only-mode.md) -- Integrity without confidentiality
  - [Threat Model](encrypt/threat-model.md) -- What PSK encryption protects and does not protect
  - API Reference: [encrypt_options](encrypt/api/encrypt_options.md) | [encrypted_socket](encrypt/api/encrypted_socket.md) | [encrypted_policy](encrypt/api/encrypted_policy.md) | [secure_key](encrypt/api/secure_key.md) | [encrypt_socket_options](encrypt/api/encrypt_socket_options.md) | [encrypt_error](encrypt/api/encrypt_error.md) | [defaults](encrypt/api/defaults.md)

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

### Multi-NIC and Receive Metadata

- [nic_group](api/nic_group.md) -- Multi-NIC orchestrator: basic_nic_group, basic_nic_monitor, dynamic_nic_group
- [nic_group_options](api/nic_group_options.md) -- nic_group_options, nic_monitor_options, server_peer_options, dedup_mode
- [recv_metadata](api/recv_metadata.md) -- recv_metadata struct (sender, optional ttl, recv_ifindex) and ttl_unknown_policy

### Configuration

- [mdns_options](api/mdns_options.md) -- Protocol timing tunables: query backoff, TTL refresh, TC handling
- [Options Deep-Dive](api/options/README.md) -- Per-field reference for every option in mdns_options, service_options, and cache_options

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
  - [Receive-Side TTL](rfc/receive-ttl.md) -- RFC 6762 §11 receive TTL verification (IP_RECVTTL, IP_PKTINFO)
  - [QU/QM Routing](rfc/quqm-routing.md) -- RFC 6762 §5.4 QU/QM response routing
  - [Negative Responses](rfc/negative-responses.md) -- RFC 6762 §6.1 NSEC negative responses
  - [Legacy Unicast](rfc/legacy-unicast.md) -- RFC 6762 §6.7 legacy unicast responses
  - [TXT Records](rfc/txt-records.md) -- RFC 6763 §6 TXT record key-value pairs

## Examples

- [examples/observer/](../examples/observer/) -- Passive mDNS traffic observation
- [examples/querier/](../examples/querier/) -- Sending mDNS queries
- [examples/service_discovery/](../examples/service_discovery/) -- One-shot service browsing
- [examples/service_server/](../examples/service_server/) -- Announcing services
- [examples/service_monitor/](../examples/service_monitor/) -- Continuous service monitoring (basic, custom group, observe mode)
- [examples/record_cache/](../examples/record_cache/) -- Standalone and wired cache usage
- [examples/asio/](../examples/asio/) -- ASIO completion token variants (callbacks, coroutines, futures)
- [examples/inproc_bus/](../examples/inproc_bus/) -- In-process mDNS scenario using inproc_bus
- [examples/nic_group/](../examples/nic_group/) -- Multi-NIC grouping: monitor-only, announce+monitor, dynamic builder
- [examples/encrypt/](../examples/encrypt/) -- Encrypted mDNS: PSK observer, key rotation, auth-only mode

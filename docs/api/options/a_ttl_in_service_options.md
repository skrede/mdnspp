# a_ttl in service_options

| | |
|---|---|
| **Type** | `std::chrono::seconds` |
| **Default** | `4500` (75 minutes) |
| **RFC** | RFC 6762 §11.3 |
| **One-liner** | TTL for A (IPv4 address) records in outgoing responses. |

## What

`a_ttl` sets the TTL on A records sent in responses. A records map a hostname to an IPv4 address (e.g., `myhost.local. A 192.168.1.100`). Queriers cache A records for `a_ttl` seconds.

RFC 6762 §11.3 recommends 4500 seconds for most record types. The default matches the RFC.

## Why

Reduce `a_ttl` when:

- The host's IPv4 address changes dynamically (DHCP lease renewal, roaming, etc.) and you want resolvers to re-query IPv4 addresses sooner.
- Operating in environments with dynamic addressing where stale IP mappings cause connection failures.

Increase `a_ttl` when:

- The IPv4 address is static infrastructure and long cache retention is desired.

## Danger

- **Reducing causes resolvers to re-query IPv4 addresses more frequently.** On networks with many hosts, short A TTLs can produce substantial query traffic at steady state.
- **Care should be taken on networks with dynamic addressing.** A cached A record pointing to a released DHCP address may be reassigned to a different host before the TTL expires, causing misdirected connections.
- Very short TTLs (seconds) cause continuous address lookups that effectively nullify the benefit of mDNS caching.

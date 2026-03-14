# aaaa_ttl in service_options

| | |
|---|---|
| **Type** | `std::chrono::seconds` |
| **Default** | `4500` (75 minutes) |
| **RFC** | RFC 6762 §11.3 |
| **One-liner** | TTL for AAAA (IPv6 address) records in outgoing responses. |

## What

`aaaa_ttl` sets the TTL on AAAA records sent in responses. AAAA records map a hostname to an IPv6 address (e.g., `myhost.local. AAAA fe80::1`). Queriers cache AAAA records for `aaaa_ttl` seconds.

RFC 6762 §11.3 recommends 4500 seconds for most record types. The default matches the RFC.

## Why

Reduce `aaaa_ttl` when:

- The host's IPv6 address is ephemeral (SLAAC privacy extensions, temporary addresses) and changes frequently.
- Operating on networks where IPv6 address lifetimes are shorter than 75 minutes.

Increase `aaaa_ttl` when:

- IPv6 addresses are static (link-local addresses on fixed-address nodes) and long cache retention is desired.

## Danger

- **Same trade-offs as `a_ttl` but for IPv6 addresses.** Reducing causes resolvers to re-query IPv6 addresses more frequently.
- IPv6 privacy extensions (RFC 4941) generate new temporary addresses periodically. On such nodes, `aaaa_ttl` should be set shorter than the privacy extension address lifetime to avoid caching a temporary address that will soon be deprecated.
- Very short TTLs on dual-stack hosts cause both A and AAAA re-queries at the same intervals, doubling address-lookup traffic.

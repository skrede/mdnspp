# legacy_unicast_ttl in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::seconds` |
| **Default** | `10` s |
| **One-liner** | TTL cap applied to all records in legacy unicast responses |

## What

`legacy_unicast_ttl` sets the maximum TTL placed in DNS records sent in response to legacy unicast queries (RFC 6762 §6.7). A legacy unicast query is one that arrives via unicast from a source port other than 5353 — typically from a non-mDNS resolver or a DNS-SD client that does not support multicast.

When such a query is received and `service_options::respond_to_legacy_unicast` is `true`, the responder's TTL values are capped at `legacy_unicast_ttl` regardless of the TTL in `record_ttl` or per-type TTL fields. A 4500-second record becomes a 10-second record in the legacy unicast response.

## Why

The 10-second default follows the RFC recommendation to prevent aggressive caching by non-mDNS resolvers. The reason is architectural: standard DNS resolvers treat TTLs at face value. If a resolver caches an mDNS record for 75 minutes, it will serve stale data long after the mDNS service has moved or disappeared — without the TTL-refresh mechanism that mDNS-aware queriers use.

Reasons to change it:

- **Reduce further** — in an environment where legacy queries must receive extremely fresh data (e.g., a proxy that bridges DNS to mDNS and wants to force frequent re-queries), setting to 1–5 seconds increases DNS re-query frequency from legacy clients.
- **Increase** — if the deployed legacy resolvers are known to be well-behaved (e.g., a custom embedded DNS client that handles TTL expiry correctly), a higher TTL reduces re-query load from those clients while still being lower than the full mDNS TTL.

## Danger

Increasing this allows legacy clients to cache records longer but violates the RFC recommendation to minimise non-mDNS cache pollution. A standard DNS resolver caching a record for 600 seconds will serve stale IPs and ports for up to 10 minutes after a service change, with no mechanism to invalidate the cache entry short of a negative response.

Setting this too low (e.g., 1 second) effectively forces every legacy DNS query to generate a new mDNS lookup cycle, significantly increasing multicast traffic on networks with legacy resolvers.

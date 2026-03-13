# txt_ttl in service_options

| | |
|---|---|
| **Type** | `std::chrono::seconds` |
| **Default** | `4500` (75 minutes) |
| **RFC** | RFC 6762 §11.3 |
| **One-liner** | TTL for TXT records in outgoing responses. |

## What

`txt_ttl` sets the TTL on TXT records sent in responses. TXT records carry arbitrary key-value metadata for a service instance (e.g., version, capabilities, path). Queriers cache TXT records for `txt_ttl` seconds.

RFC 6762 §11.3 recommends 4500 seconds for most record types. The default matches the RFC.

## Why

Reduce `txt_ttl` when:

- Service metadata (TXT key-value pairs) changes frequently and you want resolvers to re-query sooner after updates.
- TXT attributes are versioned and stale metadata causes incorrect client behaviour.

Increase `txt_ttl` when:

- Metadata is static and you want to minimise re-query traffic.

## Danger

- **Reducing causes resolvers to re-query metadata more frequently**, adding to multicast query load on the segment.
- **Increasing delays propagation of attribute changes.** If a service updates its TXT data while clients have cached the old record, those clients see the stale metadata until the old TTL expires (up to 4500 seconds by default).
- Clients that cached a TXT record under a long TTL will hold stale attributes even after the service has been restarted with new metadata.

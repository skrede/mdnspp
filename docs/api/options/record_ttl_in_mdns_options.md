# record_ttl in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::seconds` |
| **Default** | `4500` s (75 minutes) |
| **One-liner** | Default TTL for outgoing DNS resource records |

## What

`record_ttl` sets the Time-to-Live placed in the DNS wire format of all outgoing resource records (RFC 6762 §11.3). Receivers cache these records for their TTL duration. The TTL is also the basis for the `ttl_refresh_thresholds` schedule: refresh queries fire at fractions of this value.

Per the Doxygen comment in the header, `record_ttl` is applied to all outgoing records unless overridden by a per-type TTL in `service_options` (e.g., `service_options::ptr_ttl`, `srv_ttl`, `txt_ttl`, `a_ttl`, `aaaa_ttl`). When a per-type override is set in `service_options`, that value takes precedence for that record type; `record_ttl` acts as the fallback for types without a specific override.

The RFC default is 4500 seconds (75 minutes).

## Why

The default of 4500 seconds reflects the RFC recommendation for stable, long-lived services. Reasons to reduce it:

- **Ephemeral services** — a service that may disappear within minutes (e.g., a short-lived development server) should use a lower TTL (e.g., 120–300 seconds) so peers evict the record quickly after the service disappears, rather than holding a stale entry for over an hour.
- **Fast-changing infrastructure** — in a dynamic deployment where IP addresses or ports change frequently, a lower TTL shortens the window during which stale records are cached.

Reasons to increase it:

- **Ultra-stable infrastructure** — for services that never change and where minimising query traffic matters more than freshness, a higher TTL (e.g., 7200 seconds) reduces refresh query frequency.

## Danger

Reducing this shortens the period during which resolvers cache the record, increasing query traffic. A TTL of 30 seconds means every receiver re-queries within 30 seconds of last seeing the record, dramatically raising steady-state mDNS traffic on busy networks.

Increasing it delays propagation of address changes. If a service moves to a new IP and the old TTL is 7200 seconds, peers that missed the goodbye packet will attempt connections to the old address for up to two hours before their cache expires.

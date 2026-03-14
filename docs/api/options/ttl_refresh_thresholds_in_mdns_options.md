# ttl_refresh_thresholds in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::vector<double>` |
| **Default** | `{0.80, 0.85, 0.90, 0.95}` |
| **One-liner** | Fractional TTL thresholds at which refresh queries are issued |

## What

`ttl_refresh_thresholds` defines when the library proactively re-queries records that are approaching expiry (RFC 6762 §5.2). Each value is a fraction of the wire TTL elapsed since the record was inserted. When a cached record's age reaches `wire_ttl * threshold`, a refresh query is sent. The schedule is cancelled as soon as a fresh record arrives.

Values must be in the open interval `(0, 1)` and should be strictly increasing. With the default `{0.80, 0.85, 0.90, 0.95}` and a `record_ttl` of 4500 seconds (75 minutes), the refresh queries fire at:

- 3600 s (60 min) — 80% elapsed
- 3825 s (63.75 min) — 85% elapsed
- 4050 s (67.5 min) — 90% elapsed
- 4275 s (71.25 min) — 95% elapsed

Each fired query is jittered by `refresh_jitter_pct` to desynchronise simultaneous queriers.

## Why

The RFC default of four thresholds covering the final 20% of the TTL window provides four chances to receive a refreshed record before expiry, tolerating up to three missed responses. This is appropriate for most deployments.

Reasons to adjust:

- **Fewer thresholds** — on a network where responses are extremely reliable (e.g., a controlled lab), `{0.90}` reduces unnecessary query traffic while still refreshing before expiry.
- **Earlier thresholds** — on a lossy link where many packets are dropped, `{0.50, 0.65, 0.80, 0.90, 0.95}` adds earlier attempts to increase the chance of catching a response.
- **Tighter spacing near expiry** — `{0.90, 0.92, 0.94, 0.96, 0.98}` concentrates retries in the final 10%, reducing wasted traffic while still giving several attempts in the critical window.

## Danger

Fewer thresholds means fewer retry chances before expiry. If all refresh attempts fail (e.g., due to transient network loss), the record expires and the service appears to disappear — even if the service is still running. Applications that require high availability should keep at least three to four thresholds.

Earlier thresholds increase unnecessary query traffic: a threshold of `0.50` fires a refresh query when half the TTL remains, doubling the steady-state query rate. On a fleet of nodes monitoring many services, early thresholds across many records can produce substantial baseline multicast traffic.

An empty vector disables TTL-based refresh entirely — records will expire without any proactive re-query. This is only appropriate in applications that accept service expiry as normal (e.g., one-shot discovery workflows that do not need continuous monitoring).

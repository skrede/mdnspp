# refresh_jitter_pct in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `double` |
| **Default** | `0.02` |
| **One-liner** | Maximum jitter applied to each refresh query as a fraction of the wire TTL |

## What

`refresh_jitter_pct` controls how much random spread is applied to the fire times derived from `ttl_refresh_thresholds` (RFC 6762 §5.2). For each threshold-derived time point, a uniform random offset in `[0, wire_ttl * refresh_jitter_pct]` is added before the query is scheduled. This desynchronises simultaneous queriers watching the same records on the same network segment.

With the default of `0.02` and a 4500-second record, up to 90 seconds of jitter is added to each refresh fire point. Queries from ten nodes watching the same record will be spread across a 90-second window rather than all firing at the same moment.

## Why

The default 2% is calibrated to provide meaningful desynchronisation without significantly shifting the query timing away from its threshold. For a 4500-second TTL the threshold times shift by at most 90 seconds in either direction — negligible against the 4500-second record lifetime.

Reasons to adjust:

- **Larger jitter** — if many nodes are known to start simultaneously (e.g., a fleet boot event), a higher value such as `0.05` (5%) spreads the initial burst of refresh queries further. Note: only the jitter changes, not the threshold times themselves.
- **Smaller jitter** — in a controlled test environment with a single querier, reducing to `0.0` makes timing deterministic, which is useful for benchmarking or verifying backoff behaviour in unit tests.

## Danger

Setting to `0.0` disables jitter entirely. On a network with many simultaneous queriers watching the same records — common in fleet scenarios where all nodes monitor the same service type — removing jitter causes every node to fire refresh queries at the exact same time. This can produce a synchronised query burst at each TTL threshold, potentially saturating the multicast channel and causing cascading response floods.

Values above `0.1` (10%) push fire points far enough past their threshold that records may expire before a response is received if the network is slow to respond. For a record with `record_ttl = 4500s` and a threshold of `0.95`, jitter of 10% adds up to 450 seconds — potentially pushing the query past the TTL boundary.

# ptr_ttl in service_options

| | |
|---|---|
| **Type** | `std::chrono::seconds` |
| **Default** | `4500` (75 minutes) |
| **RFC** | RFC 6762 §11.3 |
| **One-liner** | TTL for PTR records in outgoing responses. |

## What

`ptr_ttl` sets the time-to-live value placed on PTR (Pointer) records when the service responds to DNS-SD queries. PTR records map a service type name (e.g., `_http._tcp.local.`) to a specific service instance name (e.g., `MyApp._http._tcp.local.`). Queriers cache PTR records for `ptr_ttl` seconds.

RFC 6762 §11.3 recommends 4500 seconds (75 minutes) for most record types. The default matches the RFC.

## Why

Reduce `ptr_ttl` when:

- Services are short-lived and you want caches to evict the entry sooner after the service departs (particularly if `send_goodbye` is disabled).
- Operating on mobile networks where service instances change frequently.

Increase `ptr_ttl` when:

- Services are permanent infrastructure and you want caches to retain discovery entries for longer between re-queries.

## Danger

- **Reducing shortens how long queriers retain the service discovery entry, increasing re-query frequency.** On large networks with many queriers this can amplify query traffic.
- Changing TTLs mid-operation (by restarting the service with different settings) can leave stale entries in remote caches with different expiry times — queriers that cached under the old TTL will hold records longer than intended.
- Very short TTLs (seconds or less) cause continuous re-queries from all active queriers; this is effectively a query storm and violates the RFC's intent of traffic minimisation.

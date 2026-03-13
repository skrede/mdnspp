# srv_ttl in service_options

| | |
|---|---|
| **Type** | `std::chrono::seconds` |
| **Default** | `4500` (75 minutes) |
| **RFC** | RFC 6762 §11.3 |
| **One-liner** | TTL for SRV records in outgoing responses. |

## What

`srv_ttl` sets the TTL on SRV (Service) records sent in responses. SRV records carry the hostname and port number for a service instance (e.g., `MyApp._http._tcp.local. SRV 0 0 8080 myhost.local.`). Queriers cache SRV records for `srv_ttl` seconds.

RFC 6762 §11.3 recommends 4500 seconds for most record types. The default matches the RFC.

## Why

Reduce `srv_ttl` when:

- The service's port number or hostname changes dynamically and you want resolvers to re-query the host/port mapping more frequently.
- Services are short-lived.

Increase `srv_ttl` when:

- The host/port mapping is stable and you want to reduce re-query frequency.

## Danger

- **Reducing causes resolvers to re-query the host/port mapping more frequently**, increasing multicast traffic on the segment.
- If port or host changes while clients have cached the old SRV record, they will continue using the old mapping until the TTL expires. Short TTLs reduce this window at the cost of more queries.
- Changing `srv_ttl` between restarts produces inconsistent cache state across queriers; each querier's cached TTL reflects the value at the time they received the record.

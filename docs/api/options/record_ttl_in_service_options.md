# record_ttl in service_options

| | |
|---|---|
| **Type** | `std::chrono::seconds` |
| **Default** | `4500` (75 minutes) |
| **RFC** | RFC 6762 §11.3 |
| **One-liner** | Fallback TTL for NSEC and meta-query PTR records when no per-record-type TTL applies. |

## What

`record_ttl` is the last-resort TTL applied to outgoing records that do not have a dedicated per-type TTL field (`ptr_ttl`, `srv_ttl`, `txt_ttl`, `a_ttl`, `aaaa_ttl`). Currently this applies to:

- NSEC (Next Secure) records used in negative responses
- PTR records sent in response to meta-queries (`_services._dns-sd._udp.local.`)

RFC 6762 §11.3 recommends 4500 seconds for most record types. The default matches the RFC.

## Why

Reduce `record_ttl` when:

- The service announcements are frequent and you want secondary records to expire sooner in caches.
- Consistency with reduced per-type TTLs is desired — if all per-type TTLs are reduced, reducing `record_ttl` keeps meta-query PTR records aligned.

Increase `record_ttl` when:

- Stable long-term infrastructure and minimal re-query traffic is prioritised.

## Danger

- **This is the last-resort TTL.** Reducing it increases re-query frequency for NSEC and meta-query PTR records.
- Reducing `record_ttl` without also reducing `ptr_ttl` (and other per-type TTLs) produces inconsistent TTLs across the service's records, which may confuse cache TTL accounting in some resolvers.
- Records currently classified under `record_ttl` may be reclassified to a dedicated per-type field in future library versions.

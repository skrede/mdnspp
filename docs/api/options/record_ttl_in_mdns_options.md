# record_ttl in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::seconds` |
| **Default** | `4500` s (75 minutes) |
| **One-liner** | Validated by the service server but not applied to outgoing records |

## What

`record_ttl` is named after the TTL of outgoing resource records (RFC 6762 §10), but no outgoing record uses it. The service server takes every TTL it sends from the per-type fields of `service_options`: `ptr_ttl`, `srv_ttl`, `txt_ttl`, `a_ttl`, `aaaa_ttl`, and `fallback_record_ttl` for NSEC, meta-query PTR and subtype PTR records (see [service_options](../service_options.md)). Refresh queries are scheduled from the wire TTL of each received record, not from this field.

The service server constructors still validate it: a non-positive `record_ttl` fails construction with `std::errc::invalid_argument`. The other peers ignore it.

## Why

There is no reason to change it. To change the TTLs a server sends, set the per-type fields of `service_options`.

## Danger

- Changing `record_ttl` does not change any TTL on the wire; a configuration that relies on it keeps the per-type defaults (4500 s for PTR and TXT, 120 s for SRV, A and AAAA).
- A zero or negative value makes the service server constructors fail.

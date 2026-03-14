# max_known_answers in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::size_t` |
| **Default** | `0` (unlimited) |
| **One-liner** | Maximum number of known-answer records included in outgoing queries |

## What

`max_known_answers` limits how many records from the local cache are included in the known-answer section of outgoing multi-question queries (RFC 6762 §7.1). Known answers allow a querier to inform responders of records it already has, so responders can suppress redundant announcements.

When non-zero, records are selected by highest remaining TTL first (the RFC-recommended criterion for prioritising which known answers to include). When the cap is reached, remaining known answers are omitted. A value of `0` means unlimited — all qualifying records are included, potentially triggering TC splitting across multiple packets if the payload exceeds `max_query_payload`.

## Why

The default of `0` (unlimited) is correct for most deployments and ensures known-answer suppression works as broadly as possible.

Reasons to set a non-zero cap:

- **Packet budget constraints** — on a link with a tight MTU where TC packet generation must be avoided, capping the known-answer list to a small number (e.g., 10) ensures the query fits in a single packet.
- **Testing** — setting a cap of `1` or `2` simplifies known-answer content in tests, making it easier to reason about expected responder behaviour.
- **Performance profiling** — limiting known answers reduces per-query serialization cost in benchmarks that focus on timing the query dispatch path rather than the cache walk.

## Danger

Setting a low cap may cause responders to re-announce records that the querier already holds. The responder cannot suppress an announcement unless it sees the querier's known answer for that record. If the querier's known-answer list is truncated, some records will be re-announced unnecessarily, increasing network traffic slightly. This does not violate correctness (the querier will still ignore duplicate announcements via its cache), but it adds avoidable overhead.

The cap does not affect incoming known-answer processing during TC accumulation — only outgoing query construction.

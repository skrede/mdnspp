# max_known_answers in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::size_t` |
| **Default** | `0` |
| **One-liner** | Not read by the library; outgoing known-answer lists are not capped |

## What

`max_known_answers` is named after the known-answer list of outgoing queries (RFC 6762 §7.1), but no part of the library reads it. The only queries that carry known answers are the service monitor's PTR queries: they include every cached PTR record whose remaining TTL is more than `ka_suppression_fraction` of its wire TTL, whatever this field holds. A list that does not fit in `max_query_payload` is split into TC continuation packets (see [max_query_payload](max_query_payload_in_mdns_options.md)).

## Why

There is no reason to set it: no value changes what goes on the wire.

## Danger

- A configuration that relies on a cap to keep queries small sends the full list.
- The field is not validated, so any value is accepted silently.

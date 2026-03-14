# ka_suppression_fraction in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `double` |
| **Default** | `0.5` |
| **One-liner** | Fraction of wire TTL used as the known-answer suppression threshold for standard queries |

## What

`ka_suppression_fraction` determines when a known answer in a received query is considered fresh enough to suppress re-announcement (RFC 6762 §7.1). A responder suppresses its announcement for a record if the querier's known-answer TTL for that record is at least `wire_ttl * ka_suppression_fraction`.

With the default of `0.5` and a record TTL of 4500 seconds, a known answer with remaining TTL >= 2250 seconds suppresses re-announcement. A known answer with remaining TTL < 2250 seconds is considered stale — the responder re-announces the record with a fresh TTL.

This field applies to the standard multicast query path. The TC accumulation path uses `tc_suppression_fraction` independently.

## Why

The default of `0.5` directly implements the RFC requirement: "A Multicast DNS querier SHOULD plan to issue a query at 80% of the record lifetime, and then if no answer is received, at 85% of the record lifetime, and then 90%, and then 95%." Records at or above half their TTL are considered sufficiently fresh.

Reasons to adjust:

- **Lower** — accepting stale known answers (e.g., `0.2`) allows the querier to suppress re-announcements with older cached records. This reduces re-announcements at the cost of accepting records that are already mostly expired — potentially allowing gaps in availability.
- **Raise** — requiring fresher known answers (e.g., `0.8`) forces responders to re-announce more frequently, keeping the querier's cache fresh at the cost of higher announcement traffic.

## Danger

Lowering accepts stale known answers. A known answer at 20% TTL remaining (e.g., 900 seconds out of 4500) will suppress re-announcement — but the querier's cached record will expire in less than 15 minutes without a refresh. If the querier fails to issue its own refresh query in time, the record disappears from its cache even though the service is still running.

Raising causes more re-announcements. A threshold of `0.9` means records at 89% TTL (e.g., 4050 of 4500 seconds remaining) are considered stale, forcing re-announcement. On a network with many queriers all holding nearly-fresh records, this can produce a cascade of redundant announcements.

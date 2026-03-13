# suppress_known_answers in service_options

| | |
|---|---|
| **Type** | `bool` |
| **Default** | `true` |
| **One-liner** | Whether the service honours known-answer suppression per RFC 6762 §7.1. |

## What

When a querier already has a record cached with a remaining TTL above the suppression threshold, it includes that record in the known-answer section of its query. RFC 6762 §7.1 specifies that a responder should suppress its reply if the querier's known answer has a remaining TTL at least half the record's original TTL.

With `suppress_known_answers = true` (the default), the service skips re-announcing records that the querier already holds with a sufficiently fresh TTL. With `false`, the service always responds regardless of what the querier reports.

The suppression threshold fraction is configured globally in `mdns_options::ka_suppression_fraction`.

## Why

Set `suppress_known_answers = false` when:

- Debugging cache state — always receiving responses helps verify what is being announced.
- Operating in an environment where querier known-answer lists are unreliable or malformed.
- Running behind a network proxy that strips known-answer records from queries.

Keep `suppress_known_answers = true` (the default) in production. It is a core RFC 6762 traffic-reduction mechanism.

## Danger

- **Disabling known-answer suppression increases multicast traffic** because the service responds to every matching query even when the querier already has a fresh record. On a busy network with many queriers this can significantly amplify response volume.
- Known-answer suppression is a fundamental RFC 6762 mechanism. Disabling it is non-standard and may trigger rate limiting or congestion on multicast-capable networks.

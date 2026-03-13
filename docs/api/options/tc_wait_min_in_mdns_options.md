# tc_wait_min in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `400` ms |
| **One-liner** | Minimum wait for accumulating truncated-response continuation packets |

## What

`tc_wait_min` defines the lower bound of the random wait applied after receiving a query with the TC (truncation) bit set (RFC 6762 §6). When a TC-flagged packet arrives, the responder starts a timer uniformly sampled from `[tc_wait_min, tc_wait_max]` before processing the aggregated known-answer set. During this window, continuation packets carrying additional known answers are collected.

The TC bit signals that the sender's known-answer list was too large to fit in a single UDP packet and that more packets will follow. The wait allows all continuation packets to arrive before the responder decides whether to suppress its announcement.

## Why

The RFC mandates a minimum of 400 ms to ensure continuation packets — which may arrive with a small delay after the initial TC packet — are captured before processing. This value should rarely be changed.

Reasons to reduce it:

- **Controlled networks with negligible jitter** — in a wired lab with sub-millisecond round-trip times, a lower value (e.g., 200 ms) can reduce visible response latency without risking missed continuation packets.

Reasons to increase it:

- **High-jitter or satellite links** — if continuation packets may arrive more than 400 ms after the initial TC packet, increasing `tc_wait_min` prevents premature processing.

## Danger

Reducing below 400 ms may cause premature response before all continuation packets have arrived on slow or high-jitter links. If the responder processes the known-answer set before all continuations are received, it may re-announce records the querier already has — increasing network traffic. More importantly, the incomplete known-answer set may cause the responder to send announcements that the querier explicitly suppressed, violating RFC 6762 §7.1.

`tc_wait_min` must always be less than or equal to `tc_wait_max`; violating this constraint produces undefined sampling behaviour.

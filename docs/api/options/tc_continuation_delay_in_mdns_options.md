# tc_continuation_delay in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::microseconds` |
| **Default** | `0` µs (no delay) |
| **One-liner** | Delay inserted between successive TC continuation packets |

## What

`tc_continuation_delay` controls the inter-packet spacing when a query must be split into multiple TC (truncation) continuation packets due to exceeding `max_query_payload` (RFC 6762 §6). With the default of `0`, all continuation packets are sent back-to-back as fast as the socket allows, subject only to OS scheduling.

A non-zero value inserts a fixed pause between each successive continuation packet, spreading the burst across time.

## Why

The RFC default is no added delay (zero). Reasons to add delay:

- **Congested links** — on a network where multicast bursts cause buffer overflow or packet loss (e.g., a busy 2.4 GHz Wi-Fi channel), inserting a small delay (e.g., 1–5 ms) between continuation packets reduces burst size at the cost of longer total transmission time for the known-answer list.
- **Rate-limited infrastructure** — some managed switches rate-limit multicast traffic per source. Spreading continuation packets with a deliberate delay avoids hitting the rate limiter.

Reasons to keep at zero:

- **Low-traffic networks** — when the total known-answer list rarely exceeds one packet's worth, this field has no practical effect. When set to zero, continuation packets are sent within the same executor drain cycle without scheduling inter-packet timers.

## Danger

Adding delay slows down large known-answer list transmission. If a query spans many continuation packets, each delayed by `tc_continuation_delay`, the total time to transmit the full known-answer set grows linearly. Receivers running the TC accumulator are waiting for all continuation packets within their `[tc_wait_min, tc_wait_max]` window — if `tc_continuation_delay * num_continuation_packets > tc_wait_max`, the last packets arrive after the accumulation window closes and are silently ignored. This means the receiver processes an incomplete known-answer set, potentially re-announcing records the querier already has.

Setting `tc_continuation_delay` must be coordinated with `tc_wait_max` to ensure all continuation packets arrive within the accumulation window.

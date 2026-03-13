# backoff_multiplier in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `double` |
| **Default** | `2.0` |
| **One-liner** | Multiplicative factor applied to the interval on each backoff step |

## What

`backoff_multiplier` determines how quickly the query interval grows between successive queries (RFC 6762 §5.2). After each query the current interval is multiplied by this value to produce the next interval, continuing until `max_interval` is reached. With the default of `2.0` the sequence starting at `initial_interval = 1s` produces delays of: 1 s, 2 s, 4 s, 8 s, 16 s, … up to `max_interval`.

## Why

The default of `2.0` (doubling) follows the RFC exactly and is the right choice for virtually all deployments. Reasons to deviate are rare:

- **Slower growth** — a value between 1.0 and 2.0 (e.g., `1.5`) stretches the backoff ramp, keeping queries more frequent for longer before reaching `max_interval`. Useful when `max_interval` is moderate (e.g., 60 seconds) and the application needs a longer "active search" window before settling into steady-state.
- **Faster growth** — a value above 2.0 (e.g., `3.0`) reaches `max_interval` very quickly, making the backoff effectively binary: one or two queries at short intervals, then immediately switching to `max_interval`. Useful when the goal is "one burst of retries then back off forever."

## Danger

Values below `1.0` cause the interval to shrink on each step, producing an unbounded query storm: each successive query fires sooner than the previous one. This violates the RFC and will saturate the network. Any value at or below `1.0` must be considered a misconfiguration.

Values significantly above `2.0` mean the backoff reaches `max_interval` after very few steps, collapsing the discovery ramp entirely. A multiplier of `10.0` with `initial_interval = 1s` jumps from 1 s directly to 10 s on the first retry, then to 100 s — making service discovery appear unresponsive after the first miss.

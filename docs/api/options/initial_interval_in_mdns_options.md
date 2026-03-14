# initial_interval in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `1000` ms (1 second) |
| **One-liner** | Starting interval for the exponential query backoff |

## What

`initial_interval` sets the delay between the first and second outgoing query in the exponential backoff sequence defined by RFC 6762 §5.2. The first query is issued immediately; the next fires after `initial_interval`, and subsequent queries double the delay each step (controlled by `backoff_multiplier`) until `max_interval` is reached.

## Why

The default of 1 second works well for most networks. Reasons to reduce it:

- **Fast service discovery** — a device with a short discovery window (e.g., a robot initializing over a 2-second deadline) benefits from a sub-second initial retry so the second query lands before the window closes.
- **Developer/test environments** — in controlled lab setups with no real mDNS traffic, faster retries reduce test latency without harming others.

Reasons to increase it:

- **Congested or power-constrained links** — on battery-operated sensors or saturated Wi-Fi, delaying the second query reduces early burst traffic at startup.

## Danger

Reducing `initial_interval` below 1 second may produce a flood of queries on crowded networks. The RFC requires exponential backoff precisely to avoid query storms; bypassing the lower bound defeats this protection. On a shared segment with many simultaneous queriers, each using a reduced `initial_interval`, the combined query rate at startup can saturate the multicast channel.

Increasing excessively delays initial discovery: a monitor with `initial_interval = 10s` will wait 10 seconds before the second query, frustrating users expecting near-instantaneous detection.

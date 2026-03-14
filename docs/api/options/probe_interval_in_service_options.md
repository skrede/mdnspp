# probe_interval in service_options

| | |
|---|---|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `250` (250 ms) |
| **RFC** | RFC 6762 §8.1 |
| **One-liner** | Interval between successive probe packets during the probe phase. |

## What

During the probe phase, the service sends `probe_count` probe packets separated by `probe_interval`. With the defaults of `probe_count = 3` and `probe_interval = 250 ms`, the full probe sequence spans approximately 500 ms before announcement begins (ignoring the initial random delay `probe_initial_delay_max`).

RFC 6762 §8.1 specifies 250 ms as the inter-probe interval. The default matches the RFC.

## Why

Reduce `probe_interval` when:

- Startup latency must be minimised and the network is reliable enough to deliver conflict responses quickly.
- Operating in a controlled local environment with minimal propagation delay.

Increase `probe_interval` when:

- Operating on high-latency or intermittently congested networks where conflict responses may arrive late.
- Conserving resources by spreading probe traffic over a longer window.

## Danger

- **Reducing increases collision detection speed but adds more traffic.** Very short intervals approach continuous probing, which burdens the multicast group.
- **Increasing delays service announcement.** With `probe_count = 3` and `probe_interval = 2000 ms`, announcement is delayed by ~4 seconds after the initial delay.
- Reducing below the RFC recommendation of 250 ms is non-standard and may not give remote nodes sufficient time to respond with a conflict.

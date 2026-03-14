# probe_initial_delay_max in service_options

| | |
|---|---|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `250` (250 ms) |
| **RFC** | RFC 6762 §8.1 |
| **One-liner** | Upper bound on the random initial delay before the first probe is sent; desynchronises simultaneous startups. |

## What

The first probe packet is not sent immediately. Instead, the library waits for a random duration uniformly drawn from `[0, probe_initial_delay_max]` before sending the first probe. This jitter is specified by RFC 6762 §8.1 to prevent all nodes on the same segment from probing simultaneously when they start at the same time.

RFC 6762 §8.1 specifies a maximum initial delay of 250 ms. The default matches the RFC.

## Why

Reduce `probe_initial_delay_max` when:

- The application requires the fastest possible startup and simultaneous-startup collisions are not a concern (e.g., a single service on the segment).
- Testing environments where deterministic timing is preferable.

Increase `probe_initial_delay_max` when:

- A large number of services start simultaneously and more desynchronisation is needed to spread out the probe traffic.

## Danger

- **Reducing to zero means all nodes on the same segment that start simultaneously will probe at the same instant**, causing collision storms and unnecessary conflict resolution rounds.
- On a segment with N services starting simultaneously, setting this to zero means N probe packets arrive at roughly the same time at every node. Each node may see a conflict, invoke `on_conflict`, rename, and re-probe — potentially causing multiple rounds of conflict resolution.
- Setting this to zero is permitted but non-compliant with RFC 6762 §8.1 in multi-host environments.

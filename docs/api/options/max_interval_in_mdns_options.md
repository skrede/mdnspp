# max_interval in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `3600000` ms (1 hour) |
| **One-liner** | Upper bound on the exponential backoff interval |

## What

`max_interval` caps the exponential backoff growth defined by RFC 6762 §5.2. Once the computed interval (doubled each step from `initial_interval` via `backoff_multiplier`) would exceed `max_interval`, it is clamped to `max_interval` and no longer grows. Subsequent queries are issued at this fixed cap.

## Why

The default of 1 hour reflects the RFC recommendation for steady-state querying on a quiet network: once a service is found, re-querying once per hour keeps the cache alive without contributing meaningful traffic.

Reasons to reduce it:

- **Dense, fast-changing networks** — robotics middleware where services appear and disappear frequently (e.g., sensor nodes joining/leaving a fleet) benefits from a lower cap such as 30–60 seconds so re-queries catch up with topology changes faster.
- **Interactive user interfaces** — a service browser that must reflect live topology may cap at 30 seconds for a responsive feel.

Reasons to increase it:

- Very rarely warranted. Increasing above 1 hour reduces steady-state queries below the RFC floor, meaning records may expire before a refresh query is sent if TTL and max_interval are mismatched.

## Danger

Reducing to seconds or minutes is appropriate for dense, fast-changing networks but increases steady-state query traffic proportionally. A cap of 5 seconds means the querier sends a query every 5 seconds indefinitely — at 1472-byte packets, this is roughly 2.3 kb/s of multicast overhead per querier. On a fleet of 100 nodes all querying at 5-second intervals, this becomes 230 kb/s of baseline mDNS multicast traffic, which may saturate 802.11 management queues on access points with poor multicast handling.

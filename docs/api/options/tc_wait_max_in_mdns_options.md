# tc_wait_max in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `500` ms |
| **One-liner** | Maximum wait for accumulating truncated-response continuation packets |

## What

`tc_wait_max` defines the upper bound of the random wait window applied after receiving a TC-flagged query (RFC 6762 §6). The actual wait is drawn uniformly from `[tc_wait_min, tc_wait_max]`. This jitter desynchronises multiple responders that simultaneously receive the same TC query so they do not all respond at the same instant.

See `tc_wait_min` for the full description of the TC accumulation mechanism.

## Why

The RFC recommends a 400–500 ms window to provide both a sufficient collection period for continuation packets and a 100 ms spread to randomise response timing across multiple responders. The 100 ms default spread (`tc_wait_max - tc_wait_min`) is calibrated for typical Ethernet and Wi-Fi latencies.

Reasons to increase it:

- **High-latency links** — if continuation packets may arrive after 400 ms, widening the upper bound (e.g., to 750 ms) ensures they are captured.
- **Dense responder environments** — a wider jitter window reduces the chance of response collisions when many nodes respond to the same TC query.

Reasons to reduce it:

- **Latency-sensitive applications** — reducing `tc_wait_max` (while keeping `tc_wait_min` at or below it) shortens the wait before the responder acts, reducing discovery latency on responsive networks.

## Danger

Increasing `tc_wait_max` lengthens known-answer collection but delays responses visible to queriers on the network. A querier that expects a response within 500 ms may time out before a responder with `tc_wait_max = 2000` ms has even started composing its reply.

`tc_wait_max` must always be greater than or equal to `tc_wait_min`. If `tc_wait_max < tc_wait_min`, the sampling range is invalid. The resulting behaviour is implementation-defined.

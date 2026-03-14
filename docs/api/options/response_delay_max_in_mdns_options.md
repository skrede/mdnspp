# response_delay_max in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `120` ms |
| **One-liner** | Maximum random delay before sending a multicast response |

## What

`response_delay_max` defines the upper bound of the random response delay window described in RFC 6762 §6. The actual delay before each multicast response is sent is uniformly sampled from `[response_delay_min, response_delay_max]`. The 100 ms spread (`120 - 20`) ensures responses from different nodes are distributed across a meaningful window rather than arriving in a tight burst.

See `response_delay_min` for the full description of the delay mechanism.

## Why

The default 120 ms upper bound is well-chosen for typical LAN/Wi-Fi topologies where round-trip times are under 10 ms and queriers wait at least 200 ms for responses. Reasons to adjust:

- **Increase** — on networks with many responders and frequent multicast collisions, widening the window to 200–500 ms reduces simultaneous transmissions, at the cost of higher maximum response latency.
- **Decrease** — in latency-sensitive applications where sub-50 ms discovery is required and the network has few responders, reducing `response_delay_max` to 50–60 ms shortens the worst-case wait while preserving some jitter.

## Danger

Increasing lengthens individual response latency. A querier that waits 200 ms for responses before assuming a service is absent will miss responses delayed beyond that window if `response_delay_max` is set higher than the querier's timeout. This creates an asymmetric interaction: the querier gives up before the responder responds, causing false "service not found" results.

Decreasing may cause response collisions on dense networks. Below 30 ms the spread between minimum and maximum is too narrow on networks with many simultaneous responders — all responses may arrive within a single MAC-layer collision window, degrading delivery reliability.

`response_delay_max` must always be greater than or equal to `response_delay_min`. If the constraint is violated the sampling range is invalid.

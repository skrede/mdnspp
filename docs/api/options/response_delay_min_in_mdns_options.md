# response_delay_min in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `20` ms |
| **One-liner** | Minimum random delay before sending a multicast response |

## What

`response_delay_min` sets the lower bound of the random delay inserted before a multicast response is sent (RFC 6762 §6). When a response is scheduled, a delay uniformly drawn from `[response_delay_min, response_delay_max]` is added to avoid simultaneous replies from multiple responders receiving the same query. No response is sent immediately upon query receipt — the RFC mandates a randomised wait.

## Why

The 20 ms default is the RFC minimum and provides a meaningful spread even on fast links. Reasons to adjust:

- **Reduce** — in a fully controlled single-responder environment (e.g., a unit test with a known single service server) removing the delay floor reduces test latency. Values approaching 0 ms are safe when only one responder exists.
- **Increase** — on extremely dense networks where many responders are expected, raising `response_delay_min` widens the jitter floor and reduces the probability of simultaneous transmissions even if all responders roll low values.

`response_delay_min` must always be less than or equal to `response_delay_max`.

## Danger

Reducing below 20 ms increases collision probability on busy links. If multiple responders all roll delays below 5 ms, their packets arrive at the querier within the same 802.11 CSMA/CA contention window, resulting in collisions or retransmissions at the MAC layer. The RFC chose 20 ms as the minimum precisely to provide enough spread to avoid this on typical Ethernet and Wi-Fi networks.

The delay is applied to all multicast responses, including proactive announcements and cache-refresh responses — not just query-triggered replies. Removing this floor entirely by setting both bounds to 0 ms synchronises all responses, which can cascade into multicast queue exhaustion on access points with limited multicast buffer space.

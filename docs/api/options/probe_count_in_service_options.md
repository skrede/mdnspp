# probe_count in service_options

| | |
|---|---|
| **Type** | `unsigned` |
| **Default** | `3` |
| **RFC** | RFC 6762 §8.1 |
| **One-liner** | Number of probe packets sent before a service is considered conflict-free and announcing begins. |

## What

Before announcing a service, the library sends `probe_count` DNS probe queries (RFC 6762 §8.1) at intervals of `probe_interval`. If no conflicting response is received during the probe window, the service is declared conflict-free and announcement begins. If a conflict is detected, `on_conflict` is invoked.

RFC 6762 §8.1 specifies three probe packets as the default. The default of `3` is the RFC-compliant value.

## Why

Reduce `probe_count` when:

- Startup latency must be minimised (e.g., embedded devices with constrained timing budgets).
- The network segment is well-managed and name conflicts are essentially impossible.

Increase `probe_count` when:

- Operating on high-latency segments where a single probe response may arrive late.
- Additional confidence about conflict detection is needed before announcing.

## Danger

- **Reducing speeds up startup but increases the chance of a name conflict going undetected.** Values below 1 skip probing entirely, which is non-compliant with RFC 6762 §8.1 and means the service never checks for conflicts before announcing.
- **Values below 1 are non-compliant** and may cause interoperability problems with implementations that perform proper conflict detection.
- On a congested network, reducing probe count means a conflicting probe may not arrive before probing concludes; the library will later invoke `on_conflict` if a conflict is detected post-announcement.

# announce_count in service_options

| | |
|---|---|
| **Type** | `unsigned` |
| **Default** | `2` |
| **One-liner** | Number of unsolicited announcement packets sent after probing completes. |

## What

After the probe phase succeeds (no conflicts detected), the service server sends `announce_count` gratuitous announcement packets to inform listeners of its presence. Announcements are sent at intervals of `announce_interval`.

RFC 6762 §8.3 specifies that a service should send at least two announcement packets. The default of `2` meets the minimum RFC requirement.

## Why

Increase `announce_count` when:

- The network has high packet loss and you want to improve the chance that at least one announcement is received.
- Deploying on lossy wireless links where a single announcement may be dropped.

Decrease to `1` when:

- Announcement traffic must be minimised (e.g., battery-constrained devices).
- The environment is reliable and a single packet is sufficient.

## Danger

- **Setting `announce_count` to `0` suppresses all announcements.** The service will not be discoverable until a querier happens to send a query. This is non-standard and not recommended.
- **High values combined with a short `announce_interval` produce a burst of packets** at service startup. On dense networks this can temporarily saturate the multicast group.
- Values below 2 are non-compliant with RFC 6762 §8.3 (though the library does not enforce a minimum).

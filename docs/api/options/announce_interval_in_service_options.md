# announce_interval in service_options

| | |
|---|---|
| **Type** | `std::chrono::milliseconds` |
| **Default** | `1000` (1 second) |
| **One-liner** | Delay between successive announcement packets after probing completes. |

## What

After the probe phase succeeds, the service sends `announce_count` announcement packets separated by `announce_interval`. For `announce_count = 2` with the default interval, the two announcements are sent 1 second apart.

RFC 6762 §8.3 recommends waiting at least 1 second between the first and second announcement. The default of 1000 ms meets this requirement.

## Why

Reduce `announce_interval` when:

- Fast startup visibility is important and the network is reliable.
- The service restarts frequently and must be re-discovered quickly.

Increase `announce_interval` when:

- Conserving bandwidth on a congested or low-bandwidth link.
- The application wants to spread announcement traffic over a longer startup window.

## Danger

- **Reducing below 1000 ms is non-compliant with RFC 6762 §8.3.** Interoperating implementations may ignore or rate-limit rapid announcements.
- **Very short intervals with high `announce_count` produce announcement storms** at startup. Combined with many simultaneously starting services this can cause significant multicast traffic.
- Setting `announce_interval` to zero sends all announcements back-to-back, which is RFC-non-compliant and may trigger rate limiting on network equipment.

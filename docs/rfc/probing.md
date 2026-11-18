# Probing and Conflict Resolution

mdnspp probes the network before claiming a service name, detecting conflicts
and optionally renaming the service via a user-supplied callback. After
probing succeeds, the server announces its records to the network before
entering the live state, and continues to monitor for conflicts while live.

**RFC Reference:** RFC 6762 section 8.1 (probing), section 8.2.1
(simultaneous probe tiebreaking), section 8.3 (announcing), section 9
(conflict resolution)

## Example

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <iostream>
#include <string>
#include <optional>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "192.168.1.42",
    };

    mdnspp::service_options opts{
        .on_conflict = [](std::string_view name, uint32_t attempt,
                          mdnspp::conflict_type) -> std::optional<std::string>
        {
            if (attempt >= 3)
                return std::nullopt; // give up
            auto new_name = "MyApp-" + std::to_string(attempt + 2) + "._http._tcp.local.";
            std::cout << "conflict on " << name << ", retrying as " << new_name << std::endl;
            return new_name;
        },
    };

    mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};

    srv.async_start(
        [](std::error_code ec)
        {
            if (ec)
                std::cerr << "start failed: " << ec.message() << std::endl;
            else
                std::cout << "server is live" << std::endl;
        },
        [&ctx](std::error_code)
        {
            ctx.stop();
        });

    ctx.run();
}
```

See also: [examples/service_server/](../../examples/service_server/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Three QU probes at 250 ms intervals | With 0–250 ms random initial delay; probe queries use message ID 0 (§18.1) |
| Implemented | All proposed unique names probed | Probe questions cover the service instance name AND the hostname, QTYPE=ANY (§8.1) |
| Implemented | Authority section carries the full proposed record set | SRV + TXT + A/AAAA, for §8.2.1 tiebreaking |
| Implemented | Simultaneous probe tiebreaking (§8.2.1) | Comparison in uncompressed form ordered by class, then type, then rdata, over the full record sets; an identical record set is NOT a conflict |
| Implemented | Tiebreak loss deferral | Loser defers by `probe_defer_delay` (default 1 s) before re-probing |
| Implemented | Probe rate limiting (§8.1) | After 15 conflicts within 10 s, each subsequent probe attempt waits 5 s |
| Implemented | Conflict callback with rename | `on_conflict` returns `std::optional<std::string>`; `std::nullopt` gives up |
| Implemented | Announcement burst after probing | Configurable `announce_count` and `announce_interval` |
| Implemented | Post-probe conflict detection (§9) | Responses observed while live that assert different rdata for the server's unique names trigger the conflict path (re-probe/rename) |

## In-Depth

### Probing state machine

When `async_start()` is called on a `service_server`, the server enters a
probe-announce-live state machine:

1. **Probing.** After a random delay of 0–250 ms, the server sends three
   probe queries at 250 ms intervals. Each probe carries two QU questions
   with QTYPE=ANY — one for the proposed service instance name and one for
   the proposed hostname — and the full proposed record set (SRV, TXT,
   A/AAAA) in the authority section for tiebreaking. Probe queries use
   message ID 0 per RFC 6762 section 18.1; loopback of the server's own
   probes is filtered by record-set identity, not by message ID.

2. **Conflict detection.** A response naming one of the probed unique names
   with different rdata is a conflict. A simultaneous probe from another
   host (a query whose authority section names the same unique names) is
   resolved by the section 8.2.1 tiebreak: both record sets are compared in
   uncompressed form, ordered by class, then type, then raw rdata bytes. If
   the local set is lexicographically smaller, the local server defers by
   `probe_defer_delay` before restarting its probe sequence. Identical
   record sets are explicitly not a conflict (fault-tolerant duplicate
   advertising).

3. **Conflict handling.** On conflict the server calls the `on_conflict`
   callback from `service_options` with the conflicting name, the attempt
   count, and the `conflict_type`. Returning a replacement name restarts
   probing with it; returning `std::nullopt` (or having no callback) tears
   the server down: `on_ready` fires with `mdns_error::probe_conflict` and
   `on_done` fires after teardown. Probing is rate-limited per section 8.1:
   after fifteen conflicts within ten seconds, every subsequent probe
   attempt is delayed by five seconds.

4. **Announcing.** After probing succeeds, the server sends an announcement
   burst: `announce_count` unsolicited responses at `announce_interval`
   intervals (defaults: 2 announcements at 1 s). The announcement contains
   all resource records (PTR, SRV, TXT, A/AAAA).

5. **Live.** After the announcement burst completes, the server is live and
   the `on_ready` handler fires with a success error code. The server
   responds to incoming queries and continues to watch incoming responses:
   per RFC 6762 section 9, a response asserting different rdata for one of
   the server's probe-verified unique names re-enters the conflict path.

### Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_conflict` | `conflict_callback` | `{}` (none) | Called on name conflict. Return the replacement name, or `std::nullopt` to give up. |
| `probe_count` | `uint8_t` | `3` | Number of probe packets. |
| `probe_interval` | `std::chrono::milliseconds` | `250` | Interval between probe packets. |
| `probe_initial_delay_max` | `std::chrono::milliseconds` | `250` | Upper bound of the random initial probe delay. |
| `probe_authority_ttl` | `std::chrono::seconds` | `120` | TTL on authority-section records in probe queries. |
| `probe_defer_delay` | `std::chrono::milliseconds` | `1000` | Deferral after losing a simultaneous-probe tiebreak. |
| `announce_count` | `uint8_t` | `2` | Number of announcement packets in the burst. |
| `announce_interval` | `std::chrono::milliseconds` | `1000` | Interval between announcement packets. |

These fields are part of `service_options`. See
[service_options](../api/service_options.md) for the full struct reference.

## See Also

- [service_options](../api/service_options.md)
- [service_server](../api/service_server.md)
- [Goodbye Packets](goodbye.md) — shutdown behavior after the live state

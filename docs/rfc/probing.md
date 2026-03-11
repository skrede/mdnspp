# Probing and Conflict Resolution

mdnspp probes the network before claiming a service name, detecting conflicts
and optionally renaming the service via a user-supplied callback. After
probing succeeds, the server announces its records to the network before
entering the live state.

**RFC Reference:** RFC 6762 section 8.1 (probing), section 8.3 (announcing)

## Example

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <iostream>
#include <string>

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
        .on_conflict = [](const std::string &name,
                          std::string &new_name,
                          unsigned attempt) -> bool
        {
            if (attempt >= 3)
                return false; // give up
            new_name = "MyApp-" + std::to_string(attempt + 2) + "._http._tcp.local.";
            std::cout << "conflict on " << name << ", retrying as " << new_name << "\n";
            return true;
        },
    };

    mdnspp::service_server srv{ctx, std::move(info), std::move(opts)};

    srv.async_start(
        [](std::error_code ec)
        {
            if (ec)
                std::cerr << "start failed: " << ec.message() << "\n";
            else
                std::cout << "server is live\n";
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
| Implemented | Three QU probes at 250 ms intervals | With 0–250 ms random initial delay |
| Implemented | Conflict detection on name match | Any response with matching name triggers conflict |
| Implemented | Conflict callback with retry | `on_conflict` callback; `true` to retry with new name |
| Implemented | Announcement burst after probing | Configurable `announce_count` and `announce_interval` |
| Not implemented | Simultaneous probe tiebreaking | RFC 6762 section 8.1 lexicographic comparison not implemented; any match = conflict |

## In-Depth

### Probing state machine

When `async_start()` is called on a `service_server`, the server enters a
probe-announce-live state machine:

1. **Probing.** After a random delay of 0–250 ms, the server sends three QU
   probe queries at 250 ms intervals. Each probe contains the proposed service
   name with the authority section carrying the SRV record. If any response
   arrives whose name matches the proposed service name or hostname, a conflict
   is detected.

2. **Conflict handling.** On conflict the server calls the `on_conflict`
   callback from `service_options`. The callback receives the conflicting name,
   a mutable reference for the new name, and the attempt count. Returning
   `true` restarts probing with the new name; returning `false` (or having no
   callback) fails the start with `mdns_error::probe_conflict` delivered to
   the `on_ready` handler.

3. **Announcing.** After probing succeeds, the server sends an announcement
   burst: `announce_count` unsolicited responses at `announce_interval`
   intervals (defaults: 2 announcements at 1 s). The announcement contains
   all resource records (PTR, SRV, TXT, A/AAAA).

4. **Live.** After the announcement burst completes, the server is live and
   the `on_ready` handler fires with a success error code. The server now
   responds to incoming queries.

### Simplification

mdnspp uses simplified conflict detection — any response with a matching name
is treated as a conflict. RFC 6762 section 8.1 describes a lexicographic
tiebreaking procedure for simultaneous probes (comparing the resource records
in the authority sections), which mdnspp does not implement.

### Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_conflict` | `conflict_callback` | `{}` (none) | Called on name conflict. Return `true` to retry with a new name. |
| `announce_count` | `unsigned` | `2` | Number of announcement packets in the burst. |
| `announce_interval` | `std::chrono::milliseconds` | `1000` | Interval between announcement packets. |

These fields are part of `service_options`. See
[service_options](../api/service_options.md) for the full struct reference.

## See Also

- [service_options](../api/service_options.md)
- [service_server](../api/service_server.md)
- [Goodbye Packets](goodbye.md) — shutdown behavior after the live state

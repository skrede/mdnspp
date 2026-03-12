# Continuous Querying and Backoff

When a service monitor performs continuous querying it must not flood the
network with repeated queries at a fixed rate. RFC 6762 section 5.2 requires
exponential backoff: the first re-query fires after 1 second, then 2 s, 4 s,
8 s, and so on up to a 60-minute ceiling. Additionally, active records close to
expiry trigger TTL refresh queries at 80%, 85%, 90%, and 95% of their remaining
TTL, each offset by a small random jitter to desynchronise simultaneous queriers.

**RFC Reference:** RFC 6762 section 5.2

## Example

Backoff and TTL refresh are automatic when using `service_monitor`. The default
`mdns_options` values are RFC-compliant:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_monitor.h>

int main()
{
    mdnspp::context ctx;

    // Backoff and TTL refresh happen automatically with default options
    mdnspp::service_monitor monitor{ctx};

    monitor.async_watch("_http._tcp.local.",
        [](std::error_code ec, mdnspp::service_event ev,
           mdnspp::service_instance inst)
        {
            // called when services appear, change, or disappear
        });

    ctx.run();
}
```

To adjust the backoff schedule (advanced use):

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/mdns_options.h>
#include <mdnspp/service_monitor.h>

int main()
{
    mdnspp::context ctx;

    mdnspp::mdns_options opts{
        .initial_interval = std::chrono::milliseconds{500}, // start at 0.5 s
        .max_interval     = std::chrono::minutes{10},        // cap at 10 min
        .backoff_multiplier = 2.0,
    };

    mdnspp::service_monitor monitor{ctx, opts};

    monitor.async_watch("_http._tcp.local.",
        [](std::error_code, mdnspp::service_event, mdnspp::service_instance) {});

    ctx.run();
}
```

See also: [examples/service_monitor/](../../examples/service_monitor/)

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Exponential backoff 1 s → 60 min | Configurable via `mdns_options` |
| Implemented | TTL refresh queries at 80/85/90/95% | With 2% random jitter per threshold |
| Implemented | Configurable backoff parameters | `initial_interval`, `max_interval`, `backoff_multiplier` |
| Not implemented | Client-side known-answer continuation (TC bit on queries) | PROTO-04 |

## In-Depth

### Backoff algorithm

The backoff state is maintained per watched service type in
`detail::query_backoff_state`. The function `detail::advance_backoff` computes
the next interval:

- **First call:** returns `opts.initial_interval` (default 1 s).
- **Subsequent calls:** multiplies the current interval by `opts.backoff_multiplier`
  (default 2.0) using floating-point arithmetic to avoid integer truncation at
  fractional multipliers (e.g., 1.5× of 1000 ms = 1500 ms, not 1000 ms).
- **Cap:** the result is clamped to `opts.max_interval` (default 1 hour).

The sequence with default options is: 1 s, 2 s, 4 s, 8 s, 16 s, 32 s, 64 s,
128 s, 256 s, 512 s, 1024 s, … 3600 s (60 min, then constant).

### TTL refresh scheduling

When a record is inserted into the cache, `make_refresh_schedule` computes a
set of absolute time points from the record's wire TTL and the thresholds in
`mdns_options::ttl_refresh_thresholds` (default: 0.80, 0.85, 0.90, 0.95).

For each threshold `t`, the fire time is:

```
fire_time = inserted_at + wire_ttl * t + jitter
```

where `jitter` is uniform-random in `[0, wire_ttl * refresh_jitter_pct]`
(default 2% of the wire TTL). Jitter desynchronises simultaneous queriers that
monitor the same record on the same network segment.

When a fire time is reached, the monitor sends fresh queries for the record's
name and type. If a fresh record arrives before all thresholds fire, the
remaining refresh schedule is cancelled and a new schedule is computed from
the updated insertion time.

### Implementation references

- `mdnspp/detail/query_backoff.h` — `query_backoff_state`, `advance_backoff`
- `mdnspp/mdns_options.h` — all tunables with RFC-sourced defaults and risk notes

## See Also

- [mdns-options](../mdns-options.md) — full `mdns_options` struct reference
- [service_monitor API](../api/service_monitor.md)
- [Traffic Reduction](traffic-reduction.md) — response delay and duplicate question suppression

# mdns_options

Protocol timing tunables for mDNS query backoff, TTL refresh, and TC handling.

## Header

```cpp
#include <mdnspp/mdns_options.h>
```

## Fields

```cpp
struct mdns_options {
    std::chrono::milliseconds initial_interval{std::chrono::seconds(1)};
    std::chrono::milliseconds max_interval{std::chrono::hours(1)};
    double                    backoff_multiplier{2.0};
    std::vector<double>       ttl_refresh_thresholds{0.80, 0.85, 0.90, 0.95};
    double                    refresh_jitter_pct{0.02};
    std::chrono::milliseconds tc_wait_min{400};
    std::chrono::milliseconds tc_wait_max{500};
    std::size_t               max_known_answers{0};
};
```

| Field | Type | Default | RFC Section | Description |
|-------|------|---------|-------------|-------------|
| `initial_interval` | `std::chrono::milliseconds` | `1s` | RFC 6762 §5.2 | Starting interval for the exponential query backoff. The first query fires immediately; the next is scheduled after this delay, doubling each time until `max_interval` is reached. |
| `max_interval` | `std::chrono::milliseconds` | `1h` | RFC 6762 §5.2 | Upper bound on the backoff interval. Once the computed interval exceeds this value it is clamped here and the backoff stops growing. |
| `backoff_multiplier` | `double` | `2.0` | RFC 6762 §5.2 | Multiplicative factor applied to the current interval on each backoff step. Values below 1.0 cause the interval to shrink, producing unbounded query storms. |
| `ttl_refresh_thresholds` | `std::vector<double>` | `{0.80, 0.85, 0.90, 0.95}` | RFC 6762 §5.2 | Fractional TTL thresholds at which refresh queries are issued. Each value represents the fraction of the wire TTL elapsed since record insertion. Values must be in (0, 1) and should be strictly increasing. |
| `refresh_jitter_pct` | `double` | `0.02` | RFC 6762 §5.2 | Maximum jitter applied to each refresh query fire point as a fraction of the wire TTL. A uniform random offset in `[0, wire_ttl * refresh_jitter_pct]` is added to desynchronize simultaneous queriers. Set to `0.0` to disable jitter. |
| `tc_wait_min` | `std::chrono::milliseconds` | `400ms` | RFC 6762 §6 | Minimum wait duration for accumulating truncated-response continuation packets. When a query arrives with the TC bit set, the responder waits a random duration in `[tc_wait_min, tc_wait_max]` before processing the aggregated known-answer set. |
| `tc_wait_max` | `std::chrono::milliseconds` | `500ms` | RFC 6762 §6 | Maximum wait duration for accumulating TC continuation packets. See `tc_wait_min`. |
| `max_known_answers` | `std::size_t` | `0` (unlimited) | RFC 6762 §7.1 | Maximum number of known-answer records included in outgoing queries. Zero means unlimited. When non-zero, limits the known-answer list to this many records (highest remaining TTL selected first). |

**Note:** All defaults are RFC-compliant. Changing them is an advanced operation: incorrect settings may violate interoperability guarantees or cause excessive network traffic.

## Usage

`mdns_options` accepts C++20 designated initializers:

```cpp
mdnspp::mdns_options opts{
    .initial_interval = std::chrono::milliseconds{500},
    .max_interval     = std::chrono::minutes{5},
};
```

`mdns_options` is passed as the last parameter before `std::error_code&` in all five `basic_*` constructors (throwing form: as last parameter; non-throwing form: before `ec`):

```cpp
// service_monitor (throwing)
mdnspp::service_monitor mon{ctx, std::move(monitor_opts), sock_opts, mdns_opts};

// service_server (throwing)
mdnspp::service_server srv{ctx, info, service_opts, sock_opts, mdns_opts};

// service_discovery (throwing)
mdnspp::service_discovery sd{ctx, timeout, sock_opts, mdns_opts};

// querier (throwing)
mdnspp::querier q{ctx, timeout, sock_opts, mdns_opts};

// observer (throwing)
mdnspp::observer obs{ctx, observer_opts, sock_opts, mdns_opts};
```

## Common Tuning Scenarios

**Dense, fast-changing network (e.g. robotics middleware):** Reduce `max_interval` to seconds or minutes, but be aware this increases steady-state query traffic proportionally.

**Disable TTL refresh (passive observation):** Clear `ttl_refresh_thresholds`:
```cpp
mdnspp::mdns_options opts{.ttl_refresh_thresholds = {}};
```

**Disable query backoff jitter (deterministic testing):** Set `refresh_jitter_pct` to zero:
```cpp
mdnspp::mdns_options opts{.refresh_jitter_pct = 0.0};
```

**Cap known-answer list size:**
```cpp
mdnspp::mdns_options opts{.max_known_answers = 10};
```

## See Also

- [mdns-options](../mdns-options.md) -- conceptual guide: how backoff, TTL refresh, and TC handling interact
- [query-backoff](../rfc/query-backoff.md) -- RFC 6762 §5.2 continuous querying implementation details
- [tc-handling](../rfc/tc-handling.md) -- RFC 6762 §6 truncated-response accumulation
- [service_monitor](service_monitor.md) -- primary consumer of `mdns_options` tunables

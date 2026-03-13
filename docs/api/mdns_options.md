# mdns_options

Protocol timing tunables for mDNS query backoff, TTL refresh, TC handling, response delays, and receive-side filtering.

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
    std::chrono::seconds      record_ttl{4500};
    std::chrono::milliseconds response_delay_min{20};
    std::chrono::milliseconds response_delay_max{120};
    std::chrono::seconds      legacy_unicast_ttl{10};
    double                    ka_suppression_fraction{0.5};
    double                    tc_suppression_fraction{0.5};
    std::size_t               max_query_payload{1472};
    std::chrono::microseconds tc_continuation_delay{0};
    unsigned                  receive_ttl_minimum{255};
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
| `record_ttl` | `std::chrono::seconds` | `4500s` | RFC 6762 §11.3 | Default TTL for outgoing DNS resource records. Applied to all outgoing records unless overridden by a per-type TTL in `service_options`. Typically 75 minutes for most record types. |
| `response_delay_min` | `std::chrono::milliseconds` | `20ms` | RFC 6762 §6 | Minimum random delay before sending a multicast response. A random delay uniformly drawn from `[response_delay_min, response_delay_max]` is applied to avoid simultaneous replies from multiple responders. |
| `response_delay_max` | `std::chrono::milliseconds` | `120ms` | RFC 6762 §6 | Maximum random delay before sending a multicast response. See `response_delay_min`. |
| `legacy_unicast_ttl` | `std::chrono::seconds` | `10s` | RFC 6762 §6.7 | TTL cap applied to all records sent in legacy unicast responses. When a query arrives via unicast from a port other than 5353, all answer record TTLs are capped at this value to prevent aggressive caching by non-mDNS resolvers. |
| `ka_suppression_fraction` | `double` | `0.5` | RFC 6762 §7.1 | Fraction of the wire TTL used as the known-answer suppression threshold for standard multicast queries. A known answer is valid (and suppresses re-announcement) when its remaining TTL is at least `wire_ttl * ka_suppression_fraction`. |
| `tc_suppression_fraction` | `double` | `0.5` | RFC 6762 §7.1 | Fraction of the wire TTL used as the suppression threshold on the TC accumulation path. Applied independently from `ka_suppression_fraction` so TC-path suppression can be tuned separately. |
| `max_query_payload` | `std::size_t` | `1472` bytes | — | Maximum UDP payload size for an outgoing query packet before it must be split into TC continuation packets. Matches Ethernet MTU minus IPv4 and UDP headers. Reduce for lower-MTU links. |
| `tc_continuation_delay` | `std::chrono::microseconds` | `0` | RFC 6762 §6 | Delay inserted between successive TC continuation packets. Zero means packets are sent back-to-back. A non-zero value rate-limits TC continuation bursts on congested links. |
| `receive_ttl_minimum` | `unsigned` | `255` | RFC 6762 §11 | Minimum IP TTL (hop limit) for received mDNS packets. Packets arriving with an IP TTL below this value are silently discarded. The value 255 enforces link-local-only reception: any forwarded packet has its IP TTL decremented below 255. |

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

**Configure legacy unicast TTL cap (reduce cache pollution from non-mDNS resolvers):**
```cpp
mdnspp::mdns_options opts{.legacy_unicast_ttl = std::chrono::seconds{5}};
```

**Adjust response delay range (narrow window for low-latency discovery):**
```cpp
mdnspp::mdns_options opts{
    .response_delay_min = std::chrono::milliseconds{20},
    .response_delay_max = std::chrono::milliseconds{40},
};
```

**Change default record TTL (shorter cache lifetime for dynamic services):**
```cpp
mdnspp::mdns_options opts{.record_ttl = std::chrono::seconds{120}};
```

## See Also

- [mdns-options](../mdns-options.md) -- conceptual guide: how backoff, TTL refresh, and TC handling interact
- [query-backoff](../rfc/query-backoff.md) -- RFC 6762 §5.2 continuous querying implementation details
- [tc-handling](../rfc/tc-handling.md) -- RFC 6762 §6 truncated-response accumulation
- [service_monitor](service_monitor.md) -- primary consumer of `mdns_options` tunables

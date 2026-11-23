# mDNS Options

> **Warning: All defaults in `mdns_options` are RFC 6762-compliant. This struct
> exists for non-standard mDNS use cases such as traffic isolation, custom
> namespaces, embedded environments, and testing. Changing any field means
> deviating from RFC 6762 and may break interoperability with standard mDNS
> implementations (Apple Bonjour, Avahi, Windows mDNS, etc.).**

## Primer

`mdns_options` is a plain struct of protocol timing tunables passed to `basic_*`
constructors in mdnspp. It controls how often queries are sent, when TTL
refresh queries fire, how long to wait for truncated-response packets, and the
receive-side IP TTL threshold for responses.

All fields default to RFC 6762-compliant values. Use designated initializers to
override specific fields:

```cpp
#include <mdnspp/mdns_options.h>

// All RFC defaults (equivalent to not passing mdns_options at all)
mdnspp::mdns_options opts{};

// Override only the fields you need
mdnspp::mdns_options opts{
    .initial_interval = std::chrono::seconds{2},
};
```

### Passing mdns_options to basic_* types

`mdns_options` is the last-before-`ec` parameter in all five throwing and
non-throwing constructors:

```cpp
mdnspp::context ctx;

// Throwing constructors (last positional parameter):
mdnspp::service_monitor mon{ctx, std::move(monitor_opts), sock_opts, mdns_opts};
mdnspp::service_discovery sd{ctx, query_opts, sock_opts, mdns_opts};
mdnspp::observer obs{ctx, observer_opts, sock_opts, mdns_opts};

// Non-throwing overloads (mdns_opts before std::error_code):
std::error_code ec;
mdnspp::service_monitor mon2{ctx, std::move(monitor_opts), sock_opts, mdns_opts, {}, ec}; // cache_options then ec
```

Pass `{}` for any earlier parameter you want to leave at its default:

```cpp
// Use all socket defaults, only change initial_interval
mdnspp::service_monitor mon{ctx, std::move(monitor_opts), {}, mdns_opts};
```

## In-Depth

### Query backoff (RFC 6762 section 5.2)

These three parameters control the exponential backoff schedule for continuous
discovery queries.

#### initial_interval

| | |
|---|---|
| **Type** | `std::chrono::milliseconds` |
| **Default** | 1 second |
| **RFC section** | 6762 §5.2 |

The first re-query fires at this interval after the initial query burst. Each
subsequent re-query doubles the interval until `max_interval` is reached.

Risk of changing: Reducing below 1 s may produce excessive query traffic on
busy networks and may be treated as a query storm by other mDNS implementations.
Increasing delays the first re-query and slows rediscovery after the initial pass.

#### max_interval

| | |
|---|---|
| **Type** | `std::chrono::milliseconds` |
| **Default** | 1 hour |
| **RFC section** | 6762 §5.2 |

The exponential backoff interval is capped at this value. Once reached, the
monitor sends one query per `max_interval` indefinitely (until stopped).

Risk of changing: Reducing to seconds or minutes is appropriate for networks
with rapid service churn &mdash; the monitor will re-query more frequently at
steady state. This increases query traffic proportionally and should only be
done when the extra traffic is acceptable.

#### backoff_multiplier

| | |
|---|---|
| **Type** | `double` |
| **Default** | 2.0 |
| **RFC section** | 6762 §5.2 |

Applied to the current backoff interval on each step: `next = min(current * multiplier, max_interval)`.

Risk of changing: Values below 1.0 cause the interval to shrink each step,
leading to unbounded query storms. Values much larger than 2.0 reach
`max_interval` in very few steps, making the backoff effectively binary (one
fast burst then one slow rate).

---

### TTL refresh (RFC 6762 section 5.2)

These parameters control when proactive refresh queries are sent to keep
known services alive before their records expire.

#### ttl_refresh_thresholds

| | |
|---|---|
| **Type** | `std::vector<double>` |
| **Default** | `{0.80, 0.85, 0.90, 0.95}` |
| **RFC section** | 6762 §5.2 |

Each value is a fraction of the wire TTL. When that fraction of the record's
lifetime has elapsed since insertion, a refresh query is sent. The schedule
covers the last 20% of the TTL window by default, giving four attempts before
expiry. Values must lie in (0, 1) and be strictly increasing; construction
fails with `std::errc::invalid_argument` otherwise.

The service monitor keeps one schedule per tracked service instance and
rebuilds it on every SRV record with a positive TTL that arrives for the
instance, so a received SRV record resets the refresh clock. Each fire point
sends one query for the instance's SRV, TXT, A and AAAA records.

Risk of changing: Fewer thresholds means fewer retries before expiry --
acceptable on stable networks but risky on unreliable links. Earlier thresholds
(e.g., `{0.50}`) trigger unnecessary traffic long before records are at risk.
An empty vector disables TTL refresh entirely.

```cpp
// Disable TTL refresh (records expire at wire TTL, no proactive queries)
mdnspp::mdns_options opts{
    .ttl_refresh_thresholds = {},
};

// Single refresh attempt at 90%
mdnspp::mdns_options opts{
    .ttl_refresh_thresholds = {0.90},
};
```

#### refresh_jitter_pct

| | |
|---|---|
| **Type** | `double` |
| **Default** | 0.02 (2%) |
| **RFC section** | 6762 §5.2 |

A uniform random offset in `[0, wire_ttl * refresh_jitter_pct]` is added to
each threshold-derived fire point to desynchronize simultaneous queriers on the
same network segment.

Risk of changing: Setting to `0.0` disables jitter entirely, which may cause
query storms when many nodes monitor the same records and all refresh at the
same threshold tick. Only disable in controlled test environments.

---

### TC handling (RFC 6762 sections 6 and 7.2)

These parameters control how the service server accumulates truncated-response
(TC-bit) continuation packets. The known-answer list of an outgoing query is not
capped: the service monitor's PTR queries, the only queries that carry known
answers, include every qualifying record, and a list too large for
`max_query_payload` is split into TC continuation packets.

#### tc_wait_min and tc_wait_max

| | |
|---|---|
| **Type** | `std::chrono::milliseconds` |
| **Default** | 400 ms and 500 ms |
| **RFC section** | 6762 §6 |

When a query arrives with the TC (Truncation) bit set, the server waits a
random duration in `[tc_wait_min, tc_wait_max]` before processing the
aggregated known-answer set. The wait accumulates continuation packets that
carry the remaining known-answer records.

Risk of changing: Reducing `tc_wait_min` below 400 ms may cause the server to
respond before all continuation packets have arrived on slow or congested links,
resulting in unnecessary re-announcements. Increasing `tc_wait_max` beyond
500 ms lengthens responses and may affect UX in interactive discovery scenarios.

---

### Receive-side TTL filtering (responses only)

These two fields control a receive-side IP TTL check on **responses**. No RFC rule
requires it: RFC 6762 §11 has only the send-side SHOULD that responses carry IP
TTL 255. The check is hardening, and queries are never dropped for their TTL.

Queries are exempt so that legacy queriers are answered. A query whose source
port is not the configured multicast port (`socket_options::multicast_group.port`,
5353 by default) is a legacy query, and RFC 6762 §6.7 requires a unicast reply to
its source address and port. A query from port 0 is a legacy query too. Such
one-shot resolvers often send with the operating system's default multicast TTL,
commonly 1, and with default options a service server answers them.

#### receive_ttl_minimum

| | |
|---|---|
| **Type** | `uint32_t` |
| **Default** | `255` |
| **RFC section** | none (RFC 6762 §11 covers only the send-side TTL) |

Minimum IP TTL (or IPv6 hop limit) for accepted incoming mDNS responses.
Responses with a TTL below this value are silently discarded. A response
forwarded by a router has its TTL decremented below 255, so the default drops
forwarded responses.

Risk of changing: reducing below 255 accepts forwarded responses and makes
cross-segment spoofing easier.

#### unknown_ttl_policy

| | |
|---|---|
| **Type** | `ttl_unknown_policy` |
| **Default** | `ttl_unknown_policy::accept` |

Disposition for responses where the IP TTL could not be extracted. Both
`default_socket` and `asio_socket` extract the TTL natively on Linux, macOS
(`recvmsg` ancillary data) and Windows (`WSARecvMsg`); extraction is
unavailable only on transports without an IP layer (e.g. custom policies,
the inproc bus) or when the platform call fails.

| Value | Behaviour |
|-------|-----------|
| `ttl_unknown_policy::accept` | Responses without extractable TTL are accepted. Default. |
| `ttl_unknown_policy::reject` | Responses without extractable TTL are discarded. Not suitable on transports without TTL extraction support. Queries are still answered. |

See [recv_metadata](api/recv_metadata.md) and [Receive-Side TTL](rfc/receive-ttl.md)
for platform extraction capabilities.

---

### Combining options

```cpp
mdnspp::mdns_options opts{
    // Tighter backoff for a fast-changing environment
    .initial_interval = std::chrono::milliseconds{500},
    .max_interval     = std::chrono::seconds{30},

    // Single refresh attempt at 90%
    .ttl_refresh_thresholds = {0.90},

    // No jitter (test environment only)
    .refresh_jitter_pct = 0.0,
};
```

## See Also

- [RFC 6762 section 5.2](rfc/query-backoff.md) &mdash; query backoff specification
- [RFC 6762 sections 6 and 7.2](rfc/tc-handling.md) &mdash; TC handling specification
- [Service Monitor](service-monitor.md) &mdash; uses mdns_options for continuous discovery
- [Policies](policies.md) &mdash; how mdns_options fits into the constructor signature

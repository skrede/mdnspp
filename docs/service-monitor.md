# Service Monitor

`service_monitor` continuously tracks services on the network. Unlike
`service_discovery`, which queries once and returns a list of records after a
silence timeout, `service_monitor` runs indefinitely: it fires callbacks when
services appear, change, or disappear, and maintains a live snapshot of all
currently-resolved services.

The monitor handles RFC 6762-compliant exponential backoff querying, TTL
refresh, and goodbye/timeout loss detection automatically. No polling or
manual re-querying is required.

## Primer

### Quick start

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/monitor_options.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::monitor_options opts{
        .on_found = [](const mdnspp::resolved_service &svc) {
            std::cout << "found: " << svc.instance_name << " @ "
                      << svc.hostname << ":" << svc.port << "\n";
        },
        .on_lost = [](const mdnspp::resolved_service &svc,
                      mdnspp::loss_reason reason) {
            std::cout << "lost: " << svc.instance_name << "\n";
        },
    };

    mdnspp::service_monitor mon{ctx, std::move(opts)};

    mon.watch("_http._tcp.local.");
    mon.async_start();

    ctx.run(); // runs until ctx.stop() is called
}
```

`monitor_options` callbacks are move-only (`std::move_only_function` internally),
so use `std::move(opts)` when passing to the constructor -- do not copy.

### Lifecycle callbacks

`on_found` fires once per newly-discovered service instance, but only after
the complete minimum record set has been collected: PTR + SRV + at least one
A or AAAA address record. Partial records accumulate silently; the callback
always delivers a fully usable `resolved_service`.

`on_updated` fires when an already-resolved service changes: a new address was
added, an existing address was removed, TXT entries changed, or the hostname
or port changed. It receives the updated `resolved_service`, an `update_event`
discriminator (`added` or `removed`), and the `dns_type` of the changed record.

`on_lost` fires when the service is no longer reachable. It delivers the
last-known `resolved_service` and a `loss_reason` explaining why.

### Difference from service_discovery

| | `service_discovery` | `service_monitor` |
|---|---|---|
| Runs until | Silence timeout | `stop()` |
| Callbacks | Single completion handler | Per-event on_found / on_updated / on_lost |
| Live snapshot | No | `services()` |
| Query scheduling | Single burst | Continuous backoff + TTL refresh |
| Use case | Enumerate once | Continuously track |

## In-Depth

### Monitor modes

The `mode` field in `monitor_options` controls how the monitor issues queries.

| Mode | Queries sent | Use case |
|------|-------------|----------|
| `discover` (default) | Exponential backoff PTR queries + TTL refresh queries | Full RFC 6762 continuous discovery |
| `ttl_refresh` | TTL refresh queries only (no initial burst) | Keep known services alive; do not actively hunt for new ones |
| `observe` | None | Passive listener; rely entirely on overheard multicast traffic |

In `observe` mode, `query_service_type()` is the only way to send a query.

```cpp
mdnspp::monitor_options opts{
    .mode = mdnspp::monitor_mode::observe,
    .on_found = [](const mdnspp::resolved_service &svc) { ... },
};
```

### watch() and unwatch()

`watch(service_type)` registers interest in a service type. Only PTR records
whose name matches a watched type are accepted into the cache; all other traffic
is discarded.

```cpp
mon.watch("_http._tcp.local.");
mon.watch("_ssh._tcp.local.");
```

`unwatch(service_type)` deregisters a service type. All currently-tracked
services of that type are immediately reported as lost via `on_lost` with
`loss_reason::unwatched`, then their cache entries and backoff state are
purged.

```cpp
mon.unwatch("_http._tcp.local.");
// on_lost fires for every live _http._tcp service with loss_reason::unwatched
```

Re-watching a previously unwatched type starts fresh: the backoff resets and
`on_found` fires again on rediscovery.

Both `watch()` and `unwatch()` are thread-safe. They post their work to the
executor thread via `P::post()` with a weak-ptr guard -- safe to call from any
thread, including before `async_start()`.

### services() snapshot

`services()` returns a `std::vector<resolved_service>` representing all
currently-live services. The snapshot is updated atomically on every state
change (service found, updated, or lost).

```cpp
auto live = mon.services();
for (const auto &svc : live)
{
    std::cout << svc.instance_name << " TTL remaining: "
              << svc.ttl_remaining.count() / 1'000'000'000 << "s\n";
}
```

Each `resolved_service` in the snapshot has `wire_ttl` (the original TTL from
the wire) and `ttl_remaining` (time until the SRV record expires) populated.

The snapshot is safe to read from any thread without holding any lock -- it
uses an atomic `shared_ptr` swap internally.

### Query scheduling

In `discover` mode the monitor sends an initial PTR query for each watched
type immediately, then re-queries on an exponentially increasing schedule per
RFC 6762 section 5.2:

- First re-query at `mdns_options::initial_interval` (default 1 s)
- Each subsequent interval doubles (multiplier 2.0) until capped at
  `mdns_options::max_interval` (default 1 hour)

In `discover` and `ttl_refresh` modes, each newly-resolved service's SRV
record TTL is tracked. Refresh queries (SRV + A + AAAA) are sent at 80%,
85%, 90%, and 95% of the wire TTL to prevent expiry. Thresholds and jitter
are controlled by `mdns_options::ttl_refresh_thresholds` and
`mdns_options::refresh_jitter_pct`.

See [mDNS Options](mdns-options.md) for tuning details.

### Explicit query functions

Two methods bypass backoff entirely and send queries immediately:

`query_service_type(service_type)` sends a PTR query for the given type.
Available in all modes; in `discover` mode it supplements automatic queries.

`query_service_instance(instance_name)` sends SRV + A + AAAA queries for a
specific instance. Useful when you know the instance name but want fresher
records before the next scheduled refresh.

Both are thread-safe (post to executor thread).

```cpp
// Force an immediate re-query for a known type
mon.query_service_type("_http._tcp.local.");

// Force an immediate refresh for a known instance
mon.query_service_instance("MyServer._http._tcp.local.");
```

### Scoped filtering

The monitor enforces a strict filter to avoid wasted work:

- PTR records are accepted only if the record name is in the watched set.
- SRV and TXT records are accepted only if the instance name is currently
  partial or live.
- A and AAAA records are accepted only if the hostname was seen in an
  accepted SRV record.

Traffic for unrelated service types and unknown hosts is silently discarded.

### loss_reason enum

| Value | Meaning |
|-------|---------|
| `timeout` | SRV TTL expired without a refresh; service presumed gone |
| `goodbye` | A goodbye packet (TTL=0 SRV) was received; 1-second grace period then lost |
| `unwatched` | `unwatch()` was called for the service type |

### update_event enum

| Value | Meaning |
|-------|---------|
| `added` | A record was added or an existing field changed (new address, TXT change, etc.) |
| `removed` | A record was removed (address expired while service is still live) |

## See Also

- [examples/service_monitor/](../examples/service_monitor/) -- runnable examples
- [API reference: service_monitor](api/service_monitor.md) -- full type documentation
- [mDNS Options](mdns-options.md) -- tuning query backoff and TTL refresh
- [Custom Policies](custom-policies.md) -- swap the executor or I/O backend

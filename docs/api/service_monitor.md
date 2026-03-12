# service_monitor

Continuously tracks mDNS services with automatic discovery, TTL refresh, and loss detection.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_service_monitor<P, Clock>` | `#include <mdnspp/basic_service_monitor.h>` |
| `mdnspp::service_monitor` (DefaultPolicy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <Policy P, typename Clock = std::chrono::steady_clock>
class basic_service_monitor;

// DefaultPolicy alias (from defaults.h)
using service_monitor = basic_service_monitor<DefaultPolicy>;
```

## Template Parameters

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `P` | satisfies `Policy` | Provides `executor_type`, `socket_type`, and `timer_type`. See [policies](../policies.md). |
| `Clock` | `std::chrono::is_clock_v<Clock>` | Clock used for TTL expiry and refresh scheduling. Default: `std::chrono::steady_clock`. Substitute `mdnspp::testing::test_clock` in unit tests for deterministic TTL control. |

## Type Aliases

```cpp
using executor_type = typename P::executor_type;
using socket_type   = typename P::socket_type;
using timer_type    = typename P::timer_type;
```

## Constructors

### Throwing

```cpp
explicit basic_service_monitor(executor_type ex,
                               monitor_options opts = {},
                               socket_options sock_opts = {},
                               mdns_options mdns_opts = {});
```

Constructs the monitor from an executor. The optional [`monitor_options`](monitor_options.md) supplies discovery callbacks and the monitoring mode. The optional `sock_opts` controls network interface selection and multicast group (see [Socket Options](../socket-options.md)). The optional [`mdns_options`](mdns_options.md) controls query backoff timing, TTL refresh thresholds, and TC accumulation windows. Throws on socket construction failure.

**Note:** `monitor_options` is move-only. Use `std::move` when passing a named variable.

### Non-throwing

```cpp
basic_service_monitor(executor_type ex,
                      monitor_options opts,
                      socket_options sock_opts,
                      mdns_options mdns_opts,
                      std::error_code &ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure. All parameters must be provided explicitly (no defaults). Check `ec` before calling `async_start()`.

## Methods

### async_start

```cpp
void async_start(monitor_completion_handler on_done = {});
```

Begins receiving mDNS multicast traffic and, depending on the configured [`monitor_mode`](monitor_options.md#monitor_mode), issues automatic discovery queries for watched service types.

- The `on_done` handler fires once when `stop()` is called. May be `nullptr`.
- In `discover` mode: issues per-type PTR queries with exponential backoff per RFC 6762 §5.2, and schedules TTL refresh queries at 80/85/90/95% of each record's wire TTL.
- In `ttl_refresh` mode: refreshes cached records proactively but does not issue discovery queries.
- In `observe` mode: passively accumulates records from overheard multicast traffic only.

Calling `async_start()` more than once is a logic error.

**Thread-safety:** Must be called on the executor thread or before the executor is running.

### stop

```cpp
void stop();
```

Idempotent. Cancels all timers and the receive loop. Fires `on_done` with `std::error_code{}`. The destructor calls `stop()` automatically for RAII safety.

**Thread-safety:** May be called from any thread. Internally posts teardown to the executor thread via a weak-pointer guard.

### watch

```cpp
void watch(std::string_view service_type);
```

Registers interest in a service type (e.g., `"_http._tcp.local."`). In `discover` mode the monitor immediately begins issuing PTR queries for this type with exponential backoff. Re-watching a previously unwatched type starts fresh: backoff resets and `on_found` fires again on rediscovery.

**Thread-safety:** May be called from any thread. Posts the registration to the executor thread via a weak-pointer guard. Safe to call before `async_start()`.

| Parameter | Description |
|-----------|-------------|
| `service_type` | Fully-qualified DNS-SD service type (e.g. `"_http._tcp.local."`) |

### unwatch

```cpp
void unwatch(std::string_view service_type);
```

Deregisters interest in a service type. Fires `on_lost(service, loss_reason::unwatched)` for every currently-tracked service of this type, then purges their cache entries and backoff state.

**Thread-safety:** May be called from any thread. Posts to the executor thread.

| Parameter | Description |
|-----------|-------------|
| `service_type` | Same fully-qualified type string passed to `watch()` |

### services

```cpp
std::vector<resolved_service> services() const;
```

Returns a snapshot of all currently-resolved services. Thread-safe via a mutex-guarded `shared_ptr` copy (the lock is held only long enough to copy the pointer). Always returns a consistent, immutable vector. Empty before any services are discovered.

The returned [`resolved_service`](resolved_service.md) values include `wire_ttl` and `ttl_remaining` populated from the SRV record's cached entry, reflecting how much TTL remains at the time `services()` is called.

**Thread-safety:** May be called from any thread.

### query_service_type

```cpp
void query_service_type(std::string_view service_type);
```

Sends an immediate PTR query for a service type, bypassing backoff. Available in all `monitor_mode` values. In `discover` mode this supplements the automatic schedule; in `observe` and `ttl_refresh` modes it is the only way to trigger a discovery query.

**Thread-safety:** May be called from any thread. Posts to the executor thread.

### query_service_instance

```cpp
void query_service_instance(std::string_view instance_name);
```

Sends immediate SRV and A/AAAA queries for a specific service instance. Useful when an instance is known by name but its address records have not yet been received.

**Thread-safety:** May be called from any thread. Posts to the executor thread.

## Lifecycle

```
construct -> watch() -> async_start() -> [running] -> stop() -> [stopped]
```

1. Construct with an executor and optional options.
2. Call `watch()` for each service type of interest (may be called before or after `async_start()`).
3. Call `async_start()` to begin the receive loop and automatic query scheduling.
4. Call `stop()` (or let the destructor do it) when done.

Destruction calls `stop()` for RAII safety.

## Supporting Types

| Type | Description |
|------|-------------|
| [`monitor_options`](monitor_options.md) | Discovery callbacks and monitoring mode |
| [`monitor_mode`](monitor_options.md#monitor_mode) | Enum: `observe`, `ttl_refresh`, `discover` |
| [`update_event`](monitor_options.md#update_event) | Enum: `added`, `removed` |
| [`loss_reason`](monitor_options.md#loss_reason) | Enum: `timeout`, `goodbye`, `unwatched` |
| [`mdns_options`](mdns_options.md) | Query backoff, TTL refresh thresholds, TC wait |
| [`resolved_service`](resolved_service.md) | The aggregated service value type |

## Usage Example

```cpp
// Continuously discover HTTP services on the local network.

#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::monitor_options opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name
                      << " at " << svc.hostname << ":" << svc.port << "\n";
        },
        .on_updated = [](const mdnspp::resolved_service &svc,
                         mdnspp::update_event event,
                         mdnspp::dns_type type)
        {
            std::cout << "updated: " << svc.instance_name
                      << " event=" << (event == mdnspp::update_event::added ? "added" : "removed")
                      << " type=" << to_string(type) << "\n";
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason reason)
        {
            const char *why = reason == mdnspp::loss_reason::timeout   ? "timeout"
                            : reason == mdnspp::loss_reason::goodbye   ? "goodbye"
                                                                       : "unwatched";
            std::cout << "lost: " << svc.instance_name << " reason=" << why << "\n";
        },
    };

    mdnspp::service_monitor mon{ctx, std::move(opts)};

    mon.watch("_http._tcp.local.");

    mon.async_start([&ctx](std::error_code ec)
    {
        if(ec)
        {
            std::cerr << "monitor error: " << ec.message() << "\n";
            ctx.stop();
        }
    });

    ctx.run();
}
```

See also the full [service_monitor examples](../../examples/service_monitor/) directory.

## See Also

- [service-monitor](../service-monitor.md) -- conceptual guide: one-shot vs continuous, monitoring modes, loss detection
- [monitor_options](monitor_options.md) -- discovery callbacks and monitoring mode reference
- [mdns_options](mdns_options.md) -- query backoff and TTL refresh tunables
- [resolved_service](resolved_service.md) -- the aggregated service value type
- [service_discovery](service_discovery.md) -- one-shot service browser (simpler API for single queries)
- [Socket Options](../socket-options.md) -- network interface selection, multicast group

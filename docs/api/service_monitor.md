# service_monitor

Continuously tracks mDNS services with automatic discovery, TTL refresh, and loss detection.

## Header and Alias

| Form | Header |
|------|--------|
| `basic_service_monitor<P, Clock>` | `#include <mdnspp/basic_service_monitor.h>` |
| `mdnspp::service_monitor` (default_policy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template form
template <policy_like P, typename Clock = std::chrono::steady_clock>
class basic_service_monitor;

// default_policy alias (from defaults.h)
using service_monitor = basic_service_monitor<default_policy>;
```

## Template Parameters

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `P` | satisfies `policy_like` | Provides `executor_type`, `socket_type`, and `timer_type`. See [policies](../policies.md). |
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
                               policy_socket_options_t<P> sock_opts = {},
                               mdns_options mdns_opts = {},
                               cache_options copts = {});
```

Constructs the monitor from an executor. The optional [`monitor_options`](monitor_options.md) supplies discovery callbacks, the error handler, and the monitoring mode. The optional `sock_opts` controls network interface selection and multicast group (see [Socket Options](../socket-options.md)); its type is `policy_socket_options_t<P>` — plain `socket_options` for the default and asio policies. The optional [`mdns_options`](mdns_options.md) controls query backoff timing, TTL refresh thresholds, and TC accumulation windows. The optional [`cache_options`](cache_options.md) controls the goodbye grace period and cache expiry callbacks. Throws `std::system_error` on socket construction failure or invalid options (`std::errc::invalid_argument`).

**Note:** `monitor_options` is move-only. Use `std::move` when passing a named variable.

### Non-throwing

```cpp
basic_service_monitor(executor_type ex,
                      monitor_options opts,
                      policy_socket_options_t<P> sock_opts,
                      mdns_options mdns_opts,
                      cache_options copts,
                      std::error_code &ec);
```

Same as the throwing constructor, but sets `ec` instead of throwing on failure (both for socket construction and for invalid options). All parameters must be provided explicitly (no defaults). Check `ec` before calling `async_start()`.

`basic_service_monitor` is non-copyable and non-movable (receive-loop and timer handlers capture `this`).

## Methods

### async_start

```cpp
void async_start(monitor_completion_handler on_done = {});
```

Begins receiving mDNS multicast traffic and, depending on the configured [`monitor_mode`](monitor_options.md#monitor_mode), issues automatic discovery queries for watched service types. Only records carried in response packets (QR=1) feed the cache; known-answer lists and probe proposals in query packets are ignored.

- The `on_done` handler fires once with `std::error_code{}` when `stop()` is called — stopping is the monitor's natural completion. May be empty.
- In `discover` mode: issues per-type PTR queries, each watch on its own exponential-backoff schedule per RFC 6762 §5.2 (a fire point for one watch never triggers a premature query for another), and schedules TTL refresh queries at 80/85/90/95% of each record's wire TTL (`mdns_options::ttl_refresh_thresholds`).
- In `ttl_refresh` mode: refreshes cached records proactively but does not issue discovery queries.
- In `observe` mode: passively accumulates records from overheard multicast traffic only.

`async_start` is one-shot: a second call completes the supplied handler with `std::errc::operation_in_progress`; a call after `stop()` completes it with `std::errc::invalid_argument`. The running monitor is unaffected.

### stop

```cpp
void stop();
```

Idempotent. Cancels all timers and the receive loop. Fires `on_done` with `std::error_code{}`. The destructor calls `stop()` automatically for RAII safety; a handler still pending at destruction is completed with `std::errc::operation_canceled` rather than dropped.

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

Sends one immediate multi-question query carrying SRV, TXT, A, and AAAA questions for a specific service instance (RFC 6762 §5 question aggregation — four questions, one packet). Useful when an instance is known by name but its address records have not yet been received. The same four-question packet is used internally for TTL refresh of resolved instances, so TXT records are refreshed alongside SRV and addresses.

**Thread-safety:** May be called from any thread. Posts to the executor thread.

### Error reporting

Fire-and-forget send failures and fatal receive errors are reported through the `monitor_options::on_error` field (`error_handler`, `void(std::error_code, std::string_view)`). The context string identifies the failure site (e.g. `"query send"`, `"receive"`). Without a handler, these errors are silently ignored.

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
            std::cout << "found: " << svc.instance_name.str()
                      << " at " << svc.hostname.str() << ":" << svc.port << std::endl;
        },
        .on_updated = [](const mdnspp::resolved_service &svc,
                         mdnspp::update_event event,
                         mdnspp::dns_type type)
        {
            std::cout << "updated: " << svc.instance_name.str()
                      << " event=" << (event == mdnspp::update_event::added ? "added" : "removed")
                      << " type=" << to_string(type) << std::endl;
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason reason)
        {
            const char *why = reason == mdnspp::loss_reason::timeout   ? "timeout"
                            : reason == mdnspp::loss_reason::goodbye   ? "goodbye"
                                                                       : "unwatched";
            std::cout << "lost: " << svc.instance_name.str() << " reason=" << why << std::endl;
        },
    };

    mdnspp::service_monitor mon{ctx, std::move(opts)};

    mon.watch("_http._tcp.local.");

    mon.async_start([&ctx](std::error_code ec)
    {
        if(ec)
        {
            std::cerr << "monitor error: " << ec.message() << std::endl;
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

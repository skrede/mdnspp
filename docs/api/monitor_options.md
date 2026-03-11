# monitor_options

Configuration struct for `service_monitor` lifecycle callbacks and monitoring mode.

## Header

```cpp
#include <mdnspp/monitor_options.h>
```

## Fields

```cpp
struct monitor_options {
    detail::move_only_function<void(const resolved_service &)>                     on_found{};
    detail::move_only_function<void(const resolved_service &, update_event, dns_type)> on_updated{};
    detail::move_only_function<void(const resolved_service &, loss_reason)>        on_lost{};
    monitor_mode                                                                   mode{monitor_mode::discover};
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `on_found` | `move_only_function<void(const resolved_service &)>` | `{}` | Fires once per fully-resolved service instance (PTR + SRV + at least one address record). Partial records are accumulated silently; the callback always receives a usable `resolved_service`. |
| `on_updated` | `move_only_function<void(const resolved_service &, update_event, dns_type)>` | `{}` | Fires when a record change alters an already-resolved service. Delivers the current service state, the direction of change (`update_event`), and the record type that changed (`dns_type`). Does not fire on TTL refreshes with identical rdata. |
| `on_lost` | `move_only_function<void(const resolved_service &, loss_reason)>` | `{}` | Fires when a service is no longer reachable. Delivers the last-known `resolved_service` and the reason for loss. |
| `mode` | `monitor_mode` | `monitor_mode::discover` | Controls whether and how the monitor issues automatic mDNS queries. |

**Note:** `monitor_options` is a move-only struct (the function fields are non-copyable). Use `std::move` when passing a named variable to the `service_monitor` constructor.

Use C++20 designated initializers for readability:

```cpp
mdnspp::monitor_options opts{
    .mode     = mdnspp::monitor_mode::observe,
    .on_found = [](const auto &svc) { /* ... */ },
};
```

## Enums

### monitor_mode

```cpp
enum class monitor_mode {
    observe,
    ttl_refresh,
    discover,
};
```

Controls the query scheduling strategy used by `service_monitor`.

| Value | Description |
|-------|-------------|
| `observe` | Passive only. No automatic queries are issued. Records are accumulated solely from overheard multicast traffic and expire naturally at TTL. Use `query_service_type()` or `query_service_instance()` for explicit queries. |
| `ttl_refresh` | No discovery queries, but cached records are proactively refreshed at 80/85/90/95% of their wire TTL (configurable via `mdns_options::ttl_refresh_thresholds`). Keeps known services alive without issuing new PTR queries. Records expire if the remote stops responding. |
| `discover` | Full RFC 6762 §5.2 continuous discovery (default). Per-type PTR queries with exponential backoff plus TTL refresh for known instances. Explicit query functions layer additional manual queries on top of automatic scheduling. |

### update_event

```cpp
enum class update_event {
    added,
    removed,
};
```

Discriminator for `on_updated` callbacks. Indicates the direction of change for a record that altered a resolved service.

| Value | Description |
|-------|-------------|
| `added` | A record was added or an existing field was modified (e.g., new address, changed TXT, new port). |
| `removed` | A record was removed without triggering full service loss (e.g., an address was lost while the SRV record is still alive). |

### loss_reason

```cpp
enum class loss_reason {
    timeout,
    goodbye,
    unwatched,
};
```

Reason code delivered to `on_lost` callbacks.

| Value | Description |
|-------|-------------|
| `timeout` | SRV record TTL expired without a refresh. The service is presumed gone. |
| `goodbye` | A goodbye packet (TTL=0) was received. After the RFC 6762 §11.3 one-second grace period the service is considered lost. |
| `unwatched` | The user called `unwatch()` for the service type. All tracked services of that type are reported as lost with this reason before their cache entries are purged. |

## Usage Example

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

mdnspp::monitor_options make_opts()
{
    return mdnspp::monitor_options{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << "\n";
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason reason)
        {
            std::cout << "lost: " << svc.instance_name
                      << (reason == mdnspp::loss_reason::goodbye ? " (goodbye)" : " (timeout)")
                      << "\n";
        },
        .mode = mdnspp::monitor_mode::discover,
    };
}
```

## See Also

- [service_monitor](service_monitor.md) -- the monitor that consumes these options
- [service-monitor](../service-monitor.md) -- conceptual guide: monitoring modes and loss detection
- [mdns_options](mdns_options.md) -- query backoff and TTL refresh tunables

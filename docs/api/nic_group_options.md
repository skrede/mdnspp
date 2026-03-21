# nic_group_options

Configuration structs and supporting types for `basic_nic_group` and `basic_nic_monitor`.

## Header

```cpp
#include <mdnspp/nic_group_options.h>
```

---

## nic_group_options

Group-level options for `basic_nic_group`.

```cpp
struct nic_group_options {
    dedup_mode                                                          dedup{dedup_mode::merged};
    detail::move_only_function<bool(const network_interface &)>         interface_filter{};
    detail::move_only_function<socket_options(const network_interface &)> socket_options_factory{};
    mdns_options                                                        mdns_opts{};
    nic_monitor_options                                                 monitor_opts{};
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dedup` | `dedup_mode` | `dedup_mode::merged` | Controls how `services()` aggregates results from multiple interfaces. |
| `interface_filter` | `move_only_function<bool(const network_interface &)>` | `{}` (none, accept all) | Predicate called for each interface. Return `false` to skip that interface. |
| `socket_options_factory` | `move_only_function<socket_options(const network_interface &)>` | `{}` (none, auto-derive) | Factory for per-interface socket options. If not set, the interface IPv4 or IPv6 address is used. |
| `mdns_opts` | `mdns_options` | default `mdns_options{}` | Forwarded to every `basic_service_monitor` and `basic_observer` instance created per interface. |
| `monitor_opts` | `nic_monitor_options` | default `nic_monitor_options{}` | Forwarded to the internal `basic_nic_monitor`. Controls the fallback polling interval. |

**Note:** `nic_group_options` is move-only because `interface_filter` and
`socket_options_factory` are `move_only_function` fields.

---

## nic_monitor_options

Options for `basic_nic_monitor`, controlling the fallback polling behavior.

```cpp
struct nic_monitor_options {
    std::chrono::milliseconds poll_interval{std::chrono::seconds(5)};
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `poll_interval` | `std::chrono::milliseconds` | 5 s | Interval between interface enumeration polls on platforms without a native backend. |

On Linux, macOS, and Windows, the native backend is used and polling is not active.
The poll interval only applies to platforms without a native NIC change notification API.

---

## server_peer_options

Options bundle for a `basic_service_server` peer within `basic_nic_group`.

```cpp
struct server_peer_options {
    service_info   info;
    service_options opts{};
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `info` | `service_info` | (required) | Service identity: name, type, hostname, port, address. |
| `opts` | `service_options` | `service_options{}` | Probing, announcement, and conflict configuration. |

`server_peer_options` bundles `service_info` and `service_options` into a single struct so
that `basic_nic_group`'s constructor can accept one vector per peer type uniformly.

---

## dedup_mode

Controls how `basic_nic_group::services()` aggregates services across interfaces.

```cpp
enum class dedup_mode {
    merged,
    per_interface,
};
```

| Value | Behavior |
|-------|----------|
| `merged` (default) | One entry per `instance_name`. When the same service is visible on multiple interfaces, the last-seen entry wins for `source_interface`. Suitable when the application wants a single logical view of the network. |
| `per_interface` | All services from all interfaces are returned, including duplicates across interfaces. Each `resolved_service` carries the `source_interface` of the interface it was seen on. Suitable for diagnostics or when per-interface attribution is required. |

---

## Type Aliases

### interface_filter

```cpp
detail::move_only_function<bool(const network_interface &)>
```

A non-copyable callable that takes a `network_interface` and returns `bool`. Returning
`true` means the interface is accepted; returning `false` means it is skipped. Set via
`nic_group_options::interface_filter`.

### socket_options_factory

```cpp
detail::move_only_function<socket_options(const network_interface &)>
```

A non-copyable callable that takes a `network_interface` and returns a `socket_options`
struct. Invoked once per interface when instances are created. Set via
`nic_group_options::socket_options_factory`.

---

## Usage Example

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::nic_group_options grp_opts{
        .dedup = mdnspp::dedup_mode::per_interface,
        .interface_filter = [](const mdnspp::network_interface &nic) -> bool
        {
            return nic.is_up && !nic.is_loopback;
        },
        .monitor_opts = {.poll_interval = std::chrono::seconds(10)},
    };

    mdnspp::monitor_options mon_opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << svc.instance_name
                      << " via " << svc.source_interface.name << "\n";
        },
    };

    mdnspp::nic_group<mdnspp::basic_service_monitor> grp{
        ctx,
        std::move(grp_opts),
        std::vector<mdnspp::monitor_options>{std::move(mon_opts)}
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    ctx.run();
}
```

## See Also

- [nic_group](nic_group.md) — the types that consume these options
- [nic-group guide](../nic-group.md) — conceptual guide with usage patterns
- [mdns_options](mdns_options.md) — query backoff, TTL, and receive-side options
- [socket_options](../socket-options.md) — per-socket network interface and multicast configuration
- [service_options](service_options.md) — probing and announcement options for service_server

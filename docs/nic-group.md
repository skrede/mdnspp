# NIC Group

`nic_group` manages a set of mDNS peers — monitors, servers, and observers — across all
active network interfaces simultaneously. When a network interface is added or removed at
runtime, `nic_group` creates or destroys the corresponding per-interface instances
automatically.

The internal NIC change detector (`basic_nic_monitor`) is owned by `nic_group` and is not
directly accessible to users. All per-interface lifecycle management is handled internally.

## Primer

### Monitor-only pattern

The most common use case: discover services across all active interfaces, getting one
merged view of the network.

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::monitor_options mon_opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name
                      << " on " << svc.source_interface.name << "\n";
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name << "\n";
        },
    };

    mdnspp::nic_group<mdnspp::basic_service_monitor> grp{
        ctx,
        mdnspp::nic_group_options{},
        std::vector<mdnspp::monitor_options>{std::move(mon_opts)}
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    ctx.run();
}
```

`nic_group<basic_service_monitor>` takes template template parameters — the peer types to
instantiate per interface. `monitor_options` is move-only; use `std::move`.

The `source_interface` field of each `resolved_service` names the interface on which the
service was discovered.

### Announce and monitor pattern

Announce a service and discover others simultaneously on all interfaces:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = "0.0.0.0",
    };

    mdnspp::monitor_options mon_opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << "\n";
        },
        .on_lost = [](const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name << "\n";
        },
    };

    mdnspp::nic_group<mdnspp::basic_service_server, mdnspp::basic_service_monitor> grp{
        ctx,
        mdnspp::nic_group_options{},
        std::vector<mdnspp::server_peer_options>{{std::move(info), mdnspp::service_options{}}},
        std::vector<mdnspp::monitor_options>{std::move(mon_opts)}
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    ctx.run();
}
```

One `basic_service_server` and one `basic_service_monitor` are created per active
interface. The constructor takes one options vector per peer type, in the same order as the
template parameter list.

### NIC monitor internals

`nic_group` owns a `basic_nic_monitor` instance that detects interface changes. Users do
not interact with it directly. The monitor uses platform-native APIs where available:

| Platform | Backend | Notes |
|----------|---------|-------|
| Linux | AF_NETLINK | RTMGRP_LINK + RTMGRP_IPV4_IFADDR + RTMGRP_IPV6_IFADDR |
| macOS | nw_path_monitor | Requires Network.framework; macOS 10.14+ |
| Windows | NotifyIpInterfaceChange | |
| Other | Timer polling | `poll_interval` from `nic_monitor_options` (default 5 s) |

When an interface changes state (same index, different address or up/down), `nic_group`
treats it as a remove-then-add sequence: existing peer instances are stopped and new ones
are created with updated socket options.

## In-Depth

### Template parameter pack (Peers...)

`basic_nic_group<P, Peers...>` accepts any combination of `basic_service_monitor`,
`basic_service_server`, and `basic_observer` as the `Peers...` pack. The constructor
takes one `std::vector<options_type>` per peer type, in pack order:

| Peer template | options_type |
|---------------|-------------|
| `basic_service_monitor` | `monitor_options` |
| `basic_service_server` | `server_peer_options` |
| `basic_observer` | `observer_options` |

Each element in the options vector corresponds to one instance created per interface.
An empty vector means no instance of that type is created per interface; a vector of
three elements means three instances per interface.

### dynamic_nic_group builder pattern

When the peer composition is not known at compile time, use `dynamic_nic_grp` (a
DefaultPolicy alias for `dynamic_nic_group<DefaultPolicy>`):

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::dynamic_nic_grp grp{ctx};

    grp.monitor({mdnspp::monitor_options{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << "\n";
        },
    }});

    grp.start();          // selects and constructs the concrete nic_group type
    grp.watch("_http._tcp.local.");

    ctx.run();
}
```

Builder methods (`monitor`, `announce`, `observe`) must be called before `start()`.
After `start()`, the concrete `basic_nic_group` instantiation is selected based on which
builder methods were called and the type-erased implementation is constructed. Calling
`watch()` or `services()` before `start()` is safe but has no effect (the internal
implementation pointer is null until `start()` is called).

All seven combinations of the three peer types are supported.

### Per-interface socket options via socket_options_factory

By default, `nic_group` derives the socket's interface address from the `network_interface`
passed to it (IPv4 first, then IPv6 if no IPv4 address is present). To customize socket
options per interface, provide a factory:

```cpp
mdnspp::nic_group_options grp_opts{
    .socket_options_factory = [](const mdnspp::network_interface &nic) -> mdnspp::socket_options
    {
        mdnspp::socket_options s;
        s.interface_address = nic.ipv4_address;
        // additional per-interface customization
        return s;
    },
};
```

`socket_options_factory` is a `move_only_function<socket_options(const network_interface &)>`.
It is invoked once per interface when an instance is created. If not set, the default
derivation from `network_interface` fields is used.

### dedup_mode

`nic_group_options::dedup` controls how `services()` aggregates results across interfaces:

| Value | Behavior |
|-------|----------|
| `dedup_mode::merged` (default) | One entry per `instance_name`. When the same service is visible on multiple interfaces, the last-seen entry wins for `source_interface`. |
| `dedup_mode::per_interface` | All services from all interfaces, including duplicates across interfaces. |

```cpp
mdnspp::nic_group_options grp_opts{
    .dedup = mdnspp::dedup_mode::per_interface,
};
```

### interface_filter

To restrict which interfaces receive peer instances, provide a filter predicate:

```cpp
mdnspp::nic_group_options grp_opts{
    .interface_filter = [](const mdnspp::network_interface &nic) -> bool
    {
        return nic.is_up && !nic.is_loopback;
    },
};
```

The filter is called for every interface reported by `basic_nic_monitor`. Returning
`false` suppresses instance creation for that interface; the interface is simply ignored.
`interface_filter` is a `move_only_function<bool(const network_interface &)>`.

### mdns_options propagation

`nic_group_options::mdns_opts` is forwarded to every `basic_service_monitor` and
`basic_observer` instance that `nic_group` creates. This controls query backoff,
TTL refresh thresholds, `receive_ttl_minimum`, and `unknown_ttl_policy` for all
per-interface monitor and observer instances uniformly.

### Lifecycle

```
construct -> watch() -> start() -> [running] -> stop() -> [stopped]
```

1. Construct with an executor, `nic_group_options`, and one options vector per peer type.
2. Optionally call `watch()` before `start()` — the watch set is accumulated and applied
   to every monitor instance created when `start()` is called.
3. Call `start()` to begin NIC monitoring and create initial per-NIC instances.
4. Call `stop()` (or let the destructor do it) when done. `stop()` is idempotent.

`watch()` and `unwatch()` are thread-safe and may be called from any thread after
construction. They are forwarded to all current and future per-interface monitor instances.

`nic_monitor_options::poll_interval` (default 5 s) controls the fallback polling rate
used on platforms without a native backend.

## See Also

- [API reference: nic_group](api/nic_group.md) — constructor signatures, method tables, dynamic_nic_group
- [API reference: nic_group_options](api/nic_group_options.md) — all option structs, dedup_mode, interface_filter, socket_options_factory
- [examples/nic_group/](../examples/nic_group/) — runnable examples

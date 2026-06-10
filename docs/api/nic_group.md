# nic_group

Multi-NIC mDNS peer orchestrator. Automatically creates and destroys per-interface
instances of mDNS peers when network interfaces are added or removed.

## Header and Aliases

| Form | Header |
|------|--------|
| `basic_nic_group<P, Peers...>` | `#include <mdnspp/basic_nic_group.h>` |
| `mdnspp::nic_group<Peers...>` (default_policy alias) | `#include <mdnspp/defaults.h>` |
| `basic_nic_monitor<P>` | `#include <mdnspp/basic_nic_monitor.h>` |
| `mdnspp::nic_monitor` (default_policy alias) | `#include <mdnspp/defaults.h>` |
| `basic_dynamic_nic_group<P>` | `#include <mdnspp/basic_nic_group.h>` |
| `mdnspp::dynamic_nic_group` (default_policy alias) | `#include <mdnspp/defaults.h>` |

```cpp
// Template forms
template <policy_like P, template <typename> class... Peers>
class basic_nic_group;

template <policy_like P>
class basic_nic_monitor;

template <policy_like P>
class basic_dynamic_nic_group;

// default_policy aliases (from defaults.h)
template <template <typename> class... Peers>
using nic_group = basic_nic_group<default_policy, Peers...>;

using nic_monitor  = basic_nic_monitor<default_policy>;
using dynamic_nic_group = basic_dynamic_nic_group<default_policy>;
```

## Template Parameters

### basic_nic_group<P, Peers...>

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `P` | satisfies `policy_like` | Provides `executor_type`, `socket_type`, and `timer_type`. See [policies](../policies.md). |
| `Peers...` | template template parameters | Any combination of `basic_service_monitor`, `basic_service_server`, and `basic_observer`. At least one must be provided. |

### basic_nic_monitor<P>

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `P` | satisfies `policy_like` | Same policy as the owning `basic_nic_group`. |

## Type Aliases

```cpp
// basic_nic_group
using executor_type = typename P::executor_type;

// basic_nic_monitor
using executor_type = typename P::executor_type;
using timer_type    = typename P::timer_type;

// basic_dynamic_nic_group
using executor_type = typename P::executor_type;
```

---

## basic_nic_group

### Constructor

```cpp
explicit basic_nic_group(executor_type ex,
                         nic_group_options grp_opts,
                         std::vector<typename detail::peer_traits<Peers, P>::options_type>... peer_opts);
```

Constructs the group. One `std::vector<options_type>` must be provided per `Peers...`
entry, in the same order as the pack. Each vector element corresponds to one instance
created per interface.

**Note:** `basic_nic_group` is non-copyable and non-movable (because the internal
`basic_nic_monitor` stores references to lambda captures). Construct in place.

| Parameter | Description |
|-----------|-------------|
| `ex` | Executor for all async operations. For default_policy this is `default_context &`. |
| `grp_opts` | Group-level options: dedup mode, interface filter, socket factory, shared mdns_options. |
| `peer_opts...` | One options vector per peer type, in pack order. |

**Options type per peer:**

| Peer template | `options_type` |
|---------------|---------------|
| `basic_service_monitor` | `monitor_options` |
| `basic_service_server` | `server_peer_options` |
| `basic_observer` | `observer_options` |

### Methods

#### start

```cpp
void start();
```

Begins NIC monitoring and creates per-NIC instances for all currently-active interfaces.
Subsequent interface additions and removals are handled automatically. Idempotent: calling
`start()` on an already-started group restarts it after a prior `stop()`.

`watch()` calls made before `start()` are accumulated and applied to every
`basic_service_monitor` instance created.

#### stop

```cpp
void stop();
```

Stops all per-interface peer instances and the internal NIC monitor. Idempotent.
The destructor calls `stop()` automatically for RAII safety.

#### services

```cpp
std::vector<resolved_service> services() const
    requires ((detail::peer_traits<Peers, P>::provides_services || ...));
```

Returns a snapshot of all currently-known services across all monitored interfaces.
Only available when `basic_service_monitor` is in the `Peers` pack.

Behavior is controlled by `nic_group_options::dedup`:
- `dedup_mode::merged` (default): one entry per `instance_name`.
- `dedup_mode::per_interface`: all services from all interfaces.

**Thread-safety:** May be called from any thread.

#### watch

```cpp
void watch(std::string_view service_type)
    requires ((detail::peer_traits<Peers, P>::provides_services || ...));
```

Registers interest in a service type across all current and future per-interface
`basic_service_monitor` instances. Only available when `basic_service_monitor` is in
the `Peers` pack. Thread-safe.

| Parameter | Description |
|-----------|-------------|
| `service_type` | Fully-qualified DNS-SD service type, e.g. `"_http._tcp.local."` |

#### unwatch

```cpp
void unwatch(std::string_view service_type)
    requires ((detail::peer_traits<Peers, P>::provides_services || ...));
```

Deregisters interest in a service type across all per-interface `basic_service_monitor`
instances. Only available when `basic_service_monitor` is in the `Peers` pack. Thread-safe.

---

## basic_nic_monitor

`basic_nic_monitor` is owned internally by `basic_nic_group`. Users do not construct it
directly in normal usage. It is documented here for completeness.

### Constructor

```cpp
explicit basic_nic_monitor(executor_type ex, nic_monitor_options opts = {});
```

Constructs and takes an initial interface snapshot. Callbacks are not yet active.

| Parameter | Description |
|-----------|-------------|
| `ex` | Executor to deliver callbacks on. |
| `opts` | Monitor options; controls the fallback poll interval. |

### Methods

#### on_added

```cpp
void on_added(detail::move_only_function<void(const network_interface &)> cb);
```

Registers a callback fired on the executor when an interface is added or its state changes
(treated as a remove then add). Called by `basic_nic_group` internally.

#### on_removed

```cpp
void on_removed(detail::move_only_function<void(const network_interface &)> cb);
```

Registers a callback fired on the executor when an interface is removed or its state
changes. Called by `basic_nic_group` internally.

#### start

```cpp
void start();
```

Begins NIC change detection. Tries platform-native backend first; falls back to
timer-based polling if unavailable.

#### stop

```cpp
void stop();
```

Stops monitoring. Idempotent. Cancels timers and platform-native handles.

#### current

```cpp
std::vector<network_interface> current() const;
```

Returns a snapshot of the current interface list. Thread-safe: the lock is held only
long enough to copy the internal `shared_ptr`.

---

## basic_dynamic_nic_group

Type-erased wrapper that selects the concrete `basic_nic_group` instantiation at `start()`
time based on which builder methods were called.

### Constructor

```cpp
explicit basic_dynamic_nic_group(executor_type ex, nic_group_options opts = {});
```

| Parameter | Description |
|-----------|-------------|
| `ex` | Executor for all async operations. |
| `opts` | Group-level options (dedup, filter, socket factory, mdns_opts). |

### Builder Methods (call before start())

#### monitor

```cpp
void monitor(std::vector<monitor_options> opts);
```

Adds a `basic_service_monitor` peer with the given options.

#### announce

```cpp
void announce(std::vector<server_peer_options> opts);
```

Adds a `basic_service_server` peer with the given options.

#### observe

```cpp
void observe(std::vector<observer_options> opts);
```

Adds a `basic_observer` peer with the given options.

### Lifecycle Methods

#### start

```cpp
void start();
```

Constructs the concrete `basic_nic_group` instantiation based on which builder methods
were called, then starts it. Must be called after all builder methods and before `watch()`.

All seven combinations of the three peer types are supported.

#### stop

```cpp
void stop();
```

Stops the underlying group. Idempotent.

### Service Methods

```cpp
std::vector<resolved_service> services() const;
void watch(std::string_view service_type);
void unwatch(std::string_view service_type);
```

Forwarded to the underlying group. `services()` and `watch()`/`unwatch()` return empty
or have no effect if the group has no monitor peer or if `start()` has not been called.

---

## Lifecycle

### basic_nic_group

```
construct -> watch() -> start() -> [running] -> stop() -> [stopped]
```

`watch()` may be called before or after `start()`. Watches are accumulated and applied
to each per-interface monitor instance when it is created.

### basic_dynamic_nic_group

```
construct -> monitor()/announce()/observe() -> start() -> watch() -> [running] -> stop()
```

Builder methods must precede `start()`. `watch()` must follow `start()`.

---

## Usage Example

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

## See Also

- [nic-group guide](../nic-group.md) — conceptual guide: patterns, dedup modes, interface filtering
- [nic_group_options](nic_group_options.md) — all option structs and supporting types
- [resolved_service](resolved_service.md) — service value type with `source_interface` field
- [service_monitor](service_monitor.md) — single-interface continuous discovery

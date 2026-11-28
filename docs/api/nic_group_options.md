# nic_group_options

Configuration structs and supporting types for `basic_nic_group` and `basic_nic_monitor`.

## Header

```cpp
#include <mdnspp/nic_group_options.h>
```

---

## nic_group_options

Group-level options for `basic_nic_group`. The template form is
`basic_nic_group_options<P>`; `mdnspp::nic_group_options` (from `defaults.h`) is the
`default_policy` alias.

```cpp
template <policy_like P>
struct basic_nic_group_options {
    dedup_mode dedup{dedup_mode::merged};
    move_only_function<bool(const network_interface &)> interface_filter{};
    move_only_function<policy_socket_options_t<P>(const network_interface &, address_family)> socket_options_factory{};
    mdns_options mdns_opts{};
    nic_monitor_options monitor_opts{};

    // Group-level, interface-stamped event callbacks (fire once per interface)
    move_only_function<void(const network_interface &, const resolved_service &)> on_found{};
    move_only_function<void(const network_interface &, const resolved_service &, update_event, dns_type)> on_updated{};
    move_only_function<void(const network_interface &, const resolved_service &, loss_reason)> on_lost{};
    move_only_function<void(const network_interface &, const endpoint &, const mdns_record_variant &)> on_record{};
    move_only_function<void(const network_interface &, std::error_code, std::string_view)> on_error{};
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `dedup` | `dedup_mode` | `dedup_mode::merged` | Controls how `services()` aggregates results from multiple interfaces. Event callbacks are unaffected — they always fire per interface. |
| `interface_filter` | `move_only_function<bool(const network_interface &)>` | `{}` (none, accept all) | Predicate called for each interface. Return `false` to skip that interface. |
| `socket_options_factory` | `move_only_function<policy_socket_options_t<P>(const network_interface &, address_family)>` | `{}` (none, auto-derive) | Factory for the socket options of one address family of one interface, called once for each family the interface has an address of. If not set, `interface_index` is the interface's index and `multicast_group` is `224.0.0.251:5353` for `address_family::ipv4` and `[ff02::fb]:5353` for `address_family::ipv6`. |
| `mdns_opts` | `mdns_options` | default `mdns_options{}` | Forwarded to every `basic_service_monitor`, `basic_service_server` and `basic_observer` instance created per interface and family. |
| `monitor_opts` | `nic_monitor_options` | default `nic_monitor_options{}` | Forwarded to the internal `basic_nic_monitor`. Controls the fallback polling interval and the optional custom enumerator. |
| `on_found` | `move_only_function<void(const network_interface &, const resolved_service &)>` | `{}` | Fired once per interface when a service instance becomes fully resolved on that interface. Requires `basic_service_monitor` in the `Peers` pack. |
| `on_updated` | `move_only_function<void(const network_interface &, const resolved_service &, update_event, dns_type)>` | `{}` | Fired once per interface when a record change alters an already-resolved service on that interface. Requires `basic_service_monitor` in the `Peers` pack. |
| `on_lost` | `move_only_function<void(const network_interface &, const resolved_service &, loss_reason)>` | `{}` | Fired once per interface when a service is no longer reachable on that interface. Requires `basic_service_monitor` in the `Peers` pack. |
| `on_record` | `move_only_function<void(const network_interface &, const endpoint &, const mdns_record_variant &)>` | `{}` | Fired per parsed record of each packet an interface's observer receives; on an interface with both address families, a record announced on both groups fires once per family. Requires `basic_observer` in the `Peers` pack. |
| `on_error` | `move_only_function<void(const network_interface &, std::error_code, std::string_view)>` | `{}` | Fired on fire-and-forget send failures and fatal receive errors of any per-NIC instance, stamped with the originating interface. Per-NIC servers use it only when `server_peer_options::service::on_error` is unset. The group itself reports a per-NIC instance that fails to construct and a factory whose options name the wrong family (see the table below). |

The leading `network_interface` parameter identifies the originating interface. The
`resolved_service` payload does not have `source_interface` populated in callbacks; the
leading parameter is authoritative. The group performs no cross-interface deduplication
of events: a service visible on two interfaces yields two `on_found` events.

Errors the group reports through `on_error` while it builds the instances of an interface. The
group never throws them out of `start()` or the event loop; the family that failed gets no
instances, and the interface's other family is unaffected:

| Context | Error | Cause |
|---------|-------|-------|
| `"service_monitor construction"` | the constructor's error, for example from socket creation | A per-NIC `basic_service_monitor` failed to construct. |
| `"service_server construction"` | the constructor's error, including `std::errc::invalid_argument` for invalid options | A per-NIC `basic_service_server` failed to construct. |
| `"observer construction"` | the constructor's error | A per-NIC `basic_observer` failed to construct. |
| `"socket_options_factory"` | `std::errc::invalid_argument` | `socket_options_factory` returned a `multicast_group` whose address is not an address of the requested family. |

**Note:** `nic_group_options` is move-only because the callback fields,
`interface_filter`, and `socket_options_factory` are `move_only_function` fields.

**Rejection of callback-bearing per-NIC options:** `basic_nic_group` (constructor) and
`basic_dynamic_nic_group` (`monitor()`/`observe()` builder methods) throw
`std::system_error` with `std::errc::invalid_argument` when a per-NIC `monitor_options`
or `observer_options` element has any callback field set. Register the group-level
callbacks above instead.

---

## nic_monitor_options

Options for `basic_nic_monitor`, controlling the fallback polling behavior and the
interface enumeration source.

```cpp
struct nic_monitor_options {
    std::chrono::milliseconds poll_interval{std::chrono::seconds(5)};
    move_only_function<std::vector<network_interface>(std::error_code &)> enumerator{};
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `poll_interval` | `std::chrono::milliseconds` | 5 s | Interval between interface enumeration polls when no native backend is active. A change is seen at the next poll, so polling detects changes up to one `poll_interval` late. |
| `enumerator` | `move_only_function<std::vector<network_interface>(std::error_code &)>` | `{}` (use `enumerate_interfaces()`) | Optional replacement for `enumerate_interfaces()`. When set, the native backends are bypassed and the monitor polls this callable every `poll_interval`. Intended for tests and for supplying a curated interface universe. |

An enumerator fills each interface's `addresses` with every address and its on-link prefix
length. The monitor reports an interface as changed (a removal followed by an addition) when
its `is_up` flag changes, when it gains or loses an address family, or when the first address
of either family changes (address or prefix length). The first IPv4 address is the first one
outside 169.254/16, or the first link-local one when there is no other; the first IPv6 address
is the first in `addresses`. Peers bind and advertise only that address, so an address added
or removed after it is not a change.

```cpp
mdnspp::nic_monitor_options mon_opts{
    .enumerator = [](std::error_code &ec)
    {
        ec.clear();
        mdnspp::network_interface nic;
        nic.name = "eth0";
        nic.index = 2;
        nic.is_up = true;
        nic.addresses.push_back({.address = {.family = mdnspp::address_family::ipv4,
                                             .bytes = {std::byte{192}, std::byte{0}, std::byte{2}, std::byte{10}}},
                                 .prefix_length = 24});
        return std::vector<mdnspp::network_interface>{nic};
    },
};
```

On Linux, macOS, and Windows the native backend is used and `poll_interval` polling is
not active unless `enumerator` is set. The Linux netlink backend drains its socket on a
100 ms timer, giving change detection a latency floor of 100 ms.

---

## server_peer_options

Options bundle for a `basic_service_server` peer within `basic_nic_group`.

```cpp
struct server_peer_options {
    service_info    info;
    service_options service{};
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `info` | `service_info` | (required) | Service identity: name, type, hostname, port, address. |
| `service` | `service_options` | `service_options{}` | Probing, announcement, and conflict configuration, including the server callbacks. |

`server_peer_options` bundles `service_info` and `service_options` into a single struct so
that `basic_nic_group`'s constructor can accept one vector per peer type uniformly.

The `service` callbacks (`on_conflict`, `on_query`, `on_tc_continuation`, `on_error`) are
per-service, not per-NIC: `basic_nic_group` forwards them to every per-NIC server instance
through a shared callable. The callable is invoked on the group executor; if that executor
is driven from multiple threads, concurrent invocation from different per-NIC instances is
possible. Note that a conflict rename returned by `on_conflict` applies only to the
instance that detected the conflict.

---

## dedup_mode

Controls how `basic_nic_group::services()` aggregates services across interfaces. Event
callbacks are not deduplicated in either mode.

```cpp
enum class dedup_mode {
    merged,
    per_interface,
};
```

| Value | Behavior |
|-------|----------|
| `merged` (default) | One entry per `instance_name`, holding the addresses found on every interface and in both address families. Its other fields and `source_interface` come from one of the interfaces that found it. Suitable when the application wants a single logical view of the network. |
| `per_interface` | One entry per `instance_name` and interface, holding the addresses that interface's IPv4 and IPv6 instances found. Each `resolved_service` carries the `source_interface` of the interface it was seen on. Suitable for diagnostics or when per-interface attribution is required. |

---

## Type Aliases

### interface_filter

```cpp
move_only_function<bool(const network_interface &)>
```

A non-copyable callable that takes a `network_interface` and returns `bool`. Returning
`true` means the interface is accepted; returning `false` means it is skipped. Set via
`nic_group_options::interface_filter`.

### socket_options_factory

```cpp
move_only_function<policy_socket_options_t<P>(const network_interface &, address_family)>
```

A non-copyable callable that takes a `network_interface` and an `address_family` and returns
the policy's socket options type (`socket_options` for `default_policy`). When an interface
appears, the group calls it once for each family the interface has an address of
(`address_family::ipv4` first) and builds one set of instances from each result. The
returned `multicast_group` must be of the requested family; otherwise the group reports
`on_error(nic, std::errc::invalid_argument, "socket_options_factory")` and builds nothing
for that family. Set via `nic_group_options::socket_options_factory`. Binding by index
needs no address text:

```cpp
grp_opts.socket_options_factory = [](const mdnspp::network_interface &nic, mdnspp::address_family family)
    -> mdnspp::socket_options
{
    mdnspp::socket_options opts{.interface_index = nic.index};
    if(family == mdnspp::address_family::ipv6)
        opts.multicast_group = {"ff02::fb", 5353};
    return opts;
};
```

---

## Usage Example

```cpp
#include <mdnspp/defaults.h>

#include <vector>
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
        .on_found = [](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc)
        {
            std::cout << svc.instance_name << " via " << nic.name << std::endl;
        },
    };

    std::vector<mdnspp::monitor_options> mon_opts;
    mon_opts.push_back(mdnspp::monitor_options{});

    mdnspp::nic_group<mdnspp::basic_service_monitor> grp{
        ctx,
        std::move(grp_opts),
        std::move(mon_opts)
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

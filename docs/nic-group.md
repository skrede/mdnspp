# NIC Group

`nic_group` manages a set of mDNS peers — monitors, servers, and observers — across all
active network interfaces simultaneously. When a network interface is added or removed at
runtime, `nic_group` creates or destroys the corresponding per-interface instances
automatically.

The internal NIC change detector (`basic_nic_monitor`) is owned by `nic_group` and is not
directly accessible to users. All per-interface lifecycle management is handled internally.

## Primer

### Monitor-only pattern

The most common use case: discover services across all active interfaces. Discovery
callbacks are registered at group level in `nic_group_options` and fire once per
interface, with the originating `network_interface` as the leading parameter.

```cpp
#include <mdnspp/defaults.h>

#include <vector>
#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::nic_group_options grp_opts{
        .on_found = [](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << " on " << nic.name << std::endl;
        },
        .on_lost = [](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc, mdnspp::loss_reason)
        {
            std::cout << "lost: " << svc.instance_name << " on " << nic.name << std::endl;
        },
    };

    // monitor_options is move-only; build the vector with push_back.
    // Per-NIC options carry tuning only — callbacks belong in nic_group_options.
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

`nic_group<basic_service_monitor>` takes template template parameters — the peer types to
instantiate per interface.

### Event callback contract

Events are delivered with per-interface semantics:

- Each group-level callback (`on_found`, `on_updated`, `on_lost`, `on_record`,
  `on_error`) fires per interface, with the originating `network_interface` as
  the leading parameter.
- Address families are invisible to `on_found`, `on_updated` and `on_lost`: the
  IPv4 and IPv6 monitors of one interface report one service. `on_found` fires
  when the first family finds it, `on_lost` when the last family has lost it, and
  `on_updated` only when the service united across both families changes (an
  address one family adds that the other already reported is no update). Every
  event carries the united service, whose addresses are those of both families.
- `on_record` fires per received packet, so on an interface with both families a
  record announced on both groups is reported once per family.
- The group performs no cross-interface deduplication of events: the same
  service instance visible on two interfaces produces **two** `on_found` events
  with distinct interfaces. Applications that want one event per logical service
  filter by `resolved_service::instance_name` themselves.
- The `resolved_service` passed to callbacks does not have `source_interface`
  populated; the leading `network_interface` parameter is authoritative.
- `services()` is unaffected: it remains the merged snapshot (see
  [dedup_mode](#dedup_mode)).

Per-NIC `monitor_options` and `observer_options` elements carry per-instance tuning only
(for example `monitor_options::mode`). The group constructor — and the
`basic_dynamic_nic_group` builder methods — reject elements whose callback fields are set
by throwing `std::system_error` with `std::errc::invalid_argument`. The group installs its
own interface-stamped forwarding callbacks into every per-NIC instance; rejecting
callback-bearing options at configure time prevents user callbacks from being silently
displaced.

`server_peer_options::service` callbacks (`on_conflict`, `on_query`, `on_tc_continuation`,
`on_error`) are per-service rather than per-NIC and are forwarded faithfully: every
per-NIC server instance invokes the same shared callable. The callable runs on the group
executor; if that executor is driven from multiple threads, it may be invoked concurrently
from different per-NIC instances.

Per-NIC servers built by one group recognize each other's records (RFC 6762 section 14).
When two interfaces of the host sit on one link, each per-NIC server hears the others'
probes, probe answers and announcements; these are not conflicts, as the host that "sees
its own Ethernet address records arrive on its wireless interface" knows them for its own.
Address records (A/AAAA) are shared by every server of the group, so services that share a
hostname, or per-NIC servers that each advertise their own interface address
(`service_info::make`), go live side by side. SRV and TXT records are shared only by the
servers built from the same `server_peer_options` element, so two elements that claim one
instance name with different data still conflict and `on_conflict` fires. A standalone
`basic_service_server` is unaffected: it does not recognize the records of another server,
even one on the same host with the same hostname.

### Announce and monitor pattern

Announce a service and discover others simultaneously on all interfaces:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <vector>
#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::nic_group_options grp_opts{
        .on_found = [](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << " on " << nic.name << std::endl;
        },
    };

    mdnspp::server_peer_options srv_opts{
        .info = {
            .service_name = "MyApp._http._tcp.local.",
            .service_type = "_http._tcp.local.",
            .hostname     = "myhost.local.",
            .port         = 8080,
            .address_ipv4 = "0.0.0.0",
        },
    };

    std::vector<mdnspp::monitor_options> mon_opts;
    mon_opts.push_back(mdnspp::monitor_options{});

    std::vector<mdnspp::server_peer_options> srv_opts_vec;
    srv_opts_vec.push_back(std::move(srv_opts));

    mdnspp::nic_group<mdnspp::basic_service_monitor, mdnspp::basic_service_server> grp{
        ctx,
        std::move(grp_opts),
        std::move(mon_opts),
        std::move(srv_opts_vec)
    };

    grp.watch("_http._tcp.local.");
    grp.start();

    ctx.run();
}
```

One `basic_service_server` and one `basic_service_monitor` are created per active
interface and address family (see [Address families](#address-families)). The constructor
takes one options vector per peer type, in the same order as the template parameter list.

### NIC monitor internals

`nic_group` owns a `basic_nic_monitor` instance that detects interface changes. Users do
not interact with it directly. The monitor uses platform-native APIs where available:

| Platform | Backend | Notes |
|----------|---------|-------|
| Linux | AF_NETLINK | RTMGRP_LINK + RTMGRP_IPV4_IFADDR + RTMGRP_IPV6_IFADDR; the socket is drained by a 100 ms timer, so change detection has a latency floor of 100 ms. A netlink buffer overflow (ENOBUFS) forces a full interface-list resynchronization. |
| macOS | nw_path_monitor | Requires Network.framework; macOS 10.14+ |
| Windows | NotifyIpInterfaceChange | |
| Other | Timer polling | `poll_interval` from `nic_monitor_options` (default 5 s) |

A custom `nic_monitor_options::enumerator` bypasses the native backends and forces the
polling path against the supplied interface list — see
[nic_group_options](api/nic_group_options.md).

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

Each element in the options vector corresponds to one instance created per interface and
address family. An empty vector means no instance of that type is created per interface; a
vector of three elements means three instances per interface and family.

### basic_dynamic_nic_group builder pattern

When the peer composition is not known at compile time, use `dynamic_nic_group` (a
default_policy alias for `basic_dynamic_nic_group<default_policy>`). The same callback
contract applies; interfaces appearing at runtime are wired to the same group-level
callbacks:

```cpp
#include <mdnspp/defaults.h>

#include <vector>
#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::nic_group_options grp_opts{
        .on_found = [](const mdnspp::network_interface &nic, const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << " on " << nic.name << std::endl;
        },
    };

    mdnspp::dynamic_nic_group grp{ctx, std::move(grp_opts)};

    std::vector<mdnspp::monitor_options> mon_opts;
    mon_opts.push_back(mdnspp::monitor_options{});
    grp.monitor(std::move(mon_opts));

    grp.start();          // selects and constructs the concrete nic_group type
    grp.watch("_http._tcp.local.");

    ctx.run();
}
```

Builder methods (`monitor`, `announce`, `observe`) must be called before `start()`.
The first `start()` selects the concrete `basic_nic_group` instantiation based on which
builder methods were called and constructs the type-erased implementation; subsequent
`start()` calls delegate to the constructed group (no-op while running, restart after
`stop()`). Calling `watch()` or `services()` before `start()` is safe but has no effect
(the internal implementation pointer is null until `start()` is called).

All seven combinations of the three peer types are supported.

### Address families

The group runs one set of instances per address family per interface: the IPv4 instances
send to and receive on `224.0.0.251`, the IPv6 instances on `ff02::fb`, each with its own
socket. An interface with addresses of both families gets both sets, an IPv6-only
interface gets only the IPv6 set, an IPv4-only interface only the IPv4 set. Each family
probes and announces on its own group, since a listener of one family does not hear the
other.

The IPv4 and IPv6 servers of one interface are siblings: they publish the same records and
recognize each other's records, so neither treats the other as a conflict. For a
`service_info` that asks for automatic addresses (`service_info::make`), both advertise the
interface's addresses of both families: the first IPv4 and the first IPv6 address of
`network_interface::addresses` (RFC 6762 section 6.2: the addresses must be valid on the
announcing link). The group takes them from the `network_interface` it was given, not from
the host's interface table, so a custom enumerator decides what is advertised. Addresses
set in `service_info` are advertised as given.

### Per-interface socket options via socket_options_factory

By default, `nic_group` binds each socket to the interface by `interface_index` and sets
`multicast_group` to `224.0.0.251:5353` for the IPv4 instances and `ff02::fb:5353` for the
IPv6 instances. To customize socket options per interface and family, provide a factory:

```cpp
mdnspp::nic_group_options grp_opts{
    .socket_options_factory = [](const mdnspp::network_interface &nic, mdnspp::address_family family)
        -> mdnspp::socket_options
    {
        mdnspp::socket_options s;
        s.interface_index = nic.index;
        if(family == mdnspp::address_family::ipv6)
            s.multicast_group = {"ff02::fb", 5353};
        // additional per-interface customization
        return s;
    },
};
```

`socket_options_factory` is a `move_only_function<socket_options(const network_interface &,
address_family)>`. It is invoked once for each family the interface has an address of, when
the instances of that family are created. The `multicast_group` it returns must belong to
the requested family: options whose group is of the other family (for example the default
`224.0.0.251` returned for `address_family::ipv6`) are reported through `on_error` with
`std::errc::invalid_argument` and the context `"socket_options_factory"`, and that family
gets no instances.

### Construction errors

`nic_group` builds every per-NIC instance with its `std::error_code` constructor. When an
instance fails to construct (a socket that cannot be opened, an invalid server option),
the group reports it through `nic_group_options::on_error` with the interface, the error
and a context naming the peer (`"service_monitor construction"`,
`"service_server construction"`, `"observer construction"`), discards the instances it
built for that interface and family, and carries on. Nothing is thrown out of `start()` or
out of the event loop that delivers interface changes. A family that failed is tried again
when its interface changes.

### Interface attribution

Each instance's socket is bound to its NIC (the default factory binds by the NIC's
index), so each instance processes only multicast received on its own NIC, even though
the operating system delivers every joined group to all sockets on the port. A custom
factory that leaves the socket unbound gives up this filtering. See
[Receive interface attribution](socket-options.md#receive-interface-attribution) for the
rule and its platform status (verified on Linux; implemented, not CI-verified on macOS or
Windows).

### Unicast replies

The per-NIC instances of one address family bind the same UDP port 5353, and mdnspp does
not tie them to a device. The operating system hands a unicast datagram addressed to the
host's port 5353 to only one of these sockets, not necessarily the one of the interface
that asked: Linux picks one by a hash of the addresses and ports, macOS and the BSDs pick
the socket that bound first, and the result on Windows is undefined (Microsoft's
documentation of `SO_REUSEADDR`).

Inside a group only server probes ask for unicast replies. Servers in a group therefore
send their probes without the unicast-response bit, so a defense arrives by multicast and
reaches the instance of the link it arrived on. The cost is that a defender that multicast
the name within the last second may answer later than it would by unicast, which is the
reason RFC 6762 §8.1 gives for probing with the unicast-response bit. A standalone server
keeps the unicast-response bit in its probes.

Between processes the limit remains: a unicast reply reaches one process on the host, and
RFC 6762 §15.1 describes the same limit for several responders sharing the port.

### dedup_mode

`nic_group_options::dedup` controls how `services()` aggregates results across interfaces.
It affects only the `services()` snapshot — event callbacks always fire per interface.

| Value | Behavior |
|-------|----------|
| `dedup_mode::merged` (default) | One entry per `instance_name`, holding the addresses found on every interface and in both address families. Its other fields and `source_interface` come from one of the interfaces that found it. |
| `dedup_mode::per_interface` | One entry per `instance_name` and interface, holding the addresses that interface's IPv4 and IPv6 instances found. |

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

`nic_group_options::mdns_opts` is forwarded to every `basic_service_monitor`,
`basic_service_server` and `basic_observer` instance that `nic_group` creates. This
controls query backoff, TTL refresh thresholds, response delays, `receive_ttl_minimum`,
`unknown_ttl_policy` and `qu_response_window` for all per-interface instances uniformly.

### Lifecycle

```
construct -> watch() -> start() -> [running] -> stop() -> [stopped]
```

1. Construct with an executor, `nic_group_options`, and one options vector per peer type.
   The constructor throws `std::system_error` (`std::errc::invalid_argument`) when a
   per-NIC `monitor_options` or `observer_options` element carries callbacks.
2. Optionally call `watch()` before `start()` — the watch set is accumulated and applied
   to every monitor instance created when `start()` is called.
3. Call `start()` to begin NIC monitoring and create initial per-NIC instances.
   `start()` on a running group is a no-op; `start()` after `stop()` restarts the group.
   A per-NIC instance that fails to construct is reported through `on_error`, not thrown
   (see [Construction errors](#construction-errors)).
4. Call `stop()` (or let the destructor do it) when done. `stop()` is idempotent.

`watch()` and `unwatch()` are thread-safe and may be called from any thread after
construction. They are forwarded to all current and future per-interface monitor instances.

`nic_monitor_options::poll_interval` (default 5 s) controls the fallback polling rate
used on platforms without a native backend.

## See Also

- [API reference: nic_group](api/nic_group.md) — constructor signatures, method tables, basic_dynamic_nic_group
- [API reference: nic_group_options](api/nic_group_options.md) — all option structs, group-level callbacks, dedup_mode, interface_filter, socket_options_factory
- [examples/nic_group/](../examples/nic_group/) — runnable examples

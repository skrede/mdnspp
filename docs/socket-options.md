# Socket Options

## Overview

`socket_options` lets you control which network interface mDNS operates on,
set the multicast TTL, and enable or disable multicast loopback. By default,
mdnspp binds to all interfaces (`INADDR_ANY`). When you need to isolate mDNS
traffic to a specific NIC &mdash; for example on a multi-homed server or an
embedded device with separate management and data networks &mdash; construct your
mdnspp types with a `socket_options` value. The interface can be selected by
OS index (`interface_index`), by name (`interface_name`), or by address
(`interface_address`).

**Headers:**

```cpp
#include <mdnspp/socket_options.h>
#include <mdnspp/network_interface.h>
```

Both headers are included transitively by `#include <mdnspp/defaults.h>`.

## socket_options struct

```cpp
namespace mdnspp {

enum class loopback_mode : uint8_t { enabled, disabled };

struct socket_options
{
    std::string interface_address{};
    std::optional<std::string> interface_name{};
    std::optional<uint32_t> interface_index{};
    endpoint multicast_group{"224.0.0.251", 5353};
    loopback_mode multicast_loopback{loopback_mode::enabled};
    std::optional<std::uint8_t> multicast_ttl{};
};

}
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interface_address` | `std::string` | `""` (empty) | Address of the NIC to bind, in the family of `multicast_group.address` (see below). With all three binding fields unset or empty the socket binds to all interfaces (`INADDR_ANY` / `in6addr_any`). |
| `interface_name` | `std::optional<std::string>` | `std::nullopt` | OS interface name of the NIC to bind (e.g. `"eth0"`, `"en0"`). Resolved at socket open via `enumerate_interfaces()`. |
| `interface_index` | `std::optional<uint32_t>` | `std::nullopt` | OS interface index of the NIC to bind. Resolved at socket open via `enumerate_interfaces()`. |
| `multicast_group` | `endpoint` | `{"224.0.0.251", 5353}` | Multicast group address and port. Change this to isolate mDNS traffic to a custom namespace. |
| `multicast_loopback` | `loopback_mode` | `loopback_mode::enabled` | Whether multicast packets are looped back to the sending host. Enabled by default so that services and clients on the same machine can communicate. |
| `multicast_ttl` | `std::optional<std::uint8_t>` | `std::nullopt` | TTL (IPv4) or hop limit (IPv6) of sent packets, multicast and unicast alike. `std::nullopt`: the native and Asio sockets send with 255, as RFC 6762 Section 11 recommends for responses (SHOULD), not with the OS default. |

The default group and port are available as `mdnspp::default_ipv4_group` (`"224.0.0.251"`),
`mdnspp::default_ipv6_group` (`"ff02::fb"`) and `mdnspp::default_port` (`5353`) in
`<mdnspp/socket_options.h>`.

### Interface selection precedence and address family

When more than one of the binding fields is set, the precedence at socket
open is `interface_index` > `interface_name` > `interface_address`: a set
`interface_index` is resolved by index only, and an unmatched index fails
socket construction with `std::errc::invalid_argument` rather than falling
back to the name or address (the same applies to an unmatched
`interface_name`). A binding is resolved once at socket open against
`enumerate_interfaces()`.

The family of `multicast_group.address` selects the socket family. An IPv4
socket names its interface by address for `IP_MULTICAST_IF` /
`IP_ADD_MEMBERSHIP`: the dotted-decimal `interface_address` as given, or the
first IPv4 address of the NIC selected by index or name. An IPv6 socket uses
the interface index directly for `IPV6_MULTICAST_IF` / `IPV6_JOIN_GROUP`: the
index of the NIC selected by index or name, or of the interface that carries
the `interface_address`. Selecting by index or name therefore picks the right
NIC even when several interfaces share a link-local address. A NIC selected
by index or name that has no address of the socket family, or an
`interface_address` of the other family, fails with
`std::errc::invalid_argument`.

An IPv6 `interface_address` is matched against the enumerated addresses by
value, so every valid text form works on every platform (`::1`,
`0:0:0:0:0:0:0:1`, upper-case hex, zero-padded groups). A scoped address
(`fe80::1%eth1` or `fe80::1%3`, RFC 4007 section 11) matches only on the
interface its zone names; without a zone, an address carried by several
interfaces resolves to the first one enumerated.

Both the native and the Asio backend apply the selected IPv6 interface to
multicast output and to group membership, whether it was chosen by
`interface_index`, `interface_name` or `interface_address`. An IPv6
`interface_address` that is not assigned to any interface fails socket
construction with `std::errc::invalid_argument` instead of falling back to
the default interface. An IPv4 `interface_address` is passed to the
operating system, which rejects one that is not assigned to a local
interface; socket construction then fails with the operating system's error
(`EADDRNOTAVAIL` on Linux).

### Unbound sockets

With no binding field set, an IPv4 socket joins the group on `INADDR_ANY` and
the operating system routes every send. A link-local IPv6 group such as
`ff02::fb` has no such route to follow, so at socket open an unbound IPv6
socket asks which interface the IPv4 mDNS group (`224.0.0.251` on the
socket's port) leaves on: it connects a throwaway UDP socket to that group,
which sends nothing, and reads the local address the route lookup chose.
When the interface carrying that address has an IPv6 address, the IPv6 socket
is pinned to it: `IPV6_MULTICAST_IF` and the group join use its index, and
`interface_index()` reports it, so the receive interface attribution below
applies to that interface. Otherwise, or when there is no route, the socket
stays unpinned and reports `0`; a failed lookup is not an error. The native
and the Asio backend pin alike. Bind an interface explicitly to use another
one. An unbound server advertises the addresses of the same interface (see
[service_info](api/service_info.md#address-auto-detection-auto_address)).

On Linux the connected source address is the one the kernel sends the group
from; the network namespace tests verify it. macOS and Windows run the same
calls; their CI runs check only that the address belongs to a local
interface.

### Receive interface attribution

A bound socket reports the index of its interface through `interface_index()`
(`default_socket`, `asio_socket`, and `encrypted_socket` over either); an
unbound IPv4 socket reports `0`, an unbound IPv6 socket the index it is
pinned to, or `0`. Every peer reads it once at construction and
silently drops a packet whose destination is a multicast address and whose
receiving interface (`recv_metadata::recv_ifindex`) is known and differs from
the bound one, queries and responses alike. A peer bound to an interface
therefore processes only multicast received on that interface, including the
packets this host sends there. Unicast packets, and packets of unknown
destination or receiving interface, are left to the local-link test (see
[recv_metadata](api/recv_metadata.md)).

The check is needed because the operating system delivers multicast to every
socket bound to the port that joined the group on any interface. The library
does not use the Linux `IP_MULTICAST_ALL` option instead. On IPv4, setting it
to 0 makes the kernel match a datagram only to sockets that joined the group
on the arrival interface, but the sockets set `SO_REUSEPORT` so that peers on
one host share the port, and with it Linux 6.18 hands the datagram to a socket
picked from the port's reuse group, whichever interface that socket joined on.
The pick happens in the kernel's early demultiplexing step for UDP (the
datagram is correct again with `net.ipv4.udp_early_demux=0`) and was
reproduced with a plain C program, so it does not depend on how the library
joins the group. The kernel source shows the same selection in Linux 6.6 and
later; other kernel versions were not tested. On IPv6, `IPV6_MULTICAST_ALL`
(Linux 4.20 and later) limits delivery to groups the socket joined, but the
kernel compares the group only, not the interface, so it cannot isolate
interfaces. macOS filters multicast by the interface a socket joined on.

Linux, IPv4 and IPv6: verified end to end by the network namespace tests,
which run two links into one host. macOS and Windows run the same rule:
implemented, but not CI-verified with several interfaces. The receive probes
there confirm its input: looped multicast reports the interface it was sent
on.

Policies may extend `socket_options`: a policy declaring a
`socket_options_type` derived from `socket_options` substitutes its own
struct via `policy_socket_options_t<P>`. The encrypted policy adds key
material this way (`encrypt_socket_options`), and the inproc policy adds
`inproc::inproc_socket_options::port_override` for simulating legacy unicast
clients on the in-process bus (see [In-Process Bus](inproc-bus.md)).

### loopback_mode enum

| Value | Effect |
|-------|--------|
| `loopback_mode::enabled` | Multicast packets sent on this socket are delivered back to the local host. |
| `loopback_mode::disabled` | Multicast packets are not looped back. |

## network_interface struct

`network_interface` describes a single network interface on the host.

```cpp
namespace mdnspp {

struct network_interface
{
    std::string name;
    std::vector<ip_network> addresses;
    uint32_t index{0};
    bool is_loopback{false};
    bool is_up{false};
};

}
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `name` | `std::string` | OS-reported interface name (e.g. `"eth0"`, `"en0"`, `"Ethernet"`). |
| `addresses` | `std::vector<ip_network>` | Every IPv4 and IPv6 address assigned to the interface, each with its on-link prefix length (see [ip_network](api/ip_address.md#ip_network)). Empty if the interface has no address. |
| `index` | `uint32_t` | OS interface index. |
| `is_loopback` | `bool` | `true` if this is the loopback interface (`lo`, `lo0`). |
| `is_up` | `bool` | `true` if the interface is currently up. |

`enumerate_interfaces()` sorts `addresses` by family (IPv4 first), then by address bytes,
then by prefix length, so a global or unique-local IPv6 address comes before a link-local
one (`fe80::/10`). Where the library picks one address of a family for an interface
(binding by `interface_name` or `interface_index`, the advertised address of an
`auto_address` service, and the default `nic_group` socket options), it takes the first
address of that family in `addresses`, which for `enumerate_interfaces()` is the first in
this order.

The prefix length is the on-link prefix. On Linux and macOS it is counted from the
`getifaddrs` netmask; on Windows it is `IP_ADAPTER_UNICAST_ADDRESS::OnLinkPrefixLength`,
which the Windows SDK declares when it targets Windows Vista or later (`_WIN32_WINNT`
`0x0600` or higher, the SDK default). The loopback interface reports `127.0.0.1/8` and
`::1/128`. macOS embeds the interface scope in bytes 2 and 3 of a link-local address
returned by `getifaddrs`; the library clears them, so a link-local address reads as
`fe80::...` on every platform.

## enumerate_interfaces()

Returns all network interfaces on the host. Two overloads are available:

```cpp
// Throwing overload -- throws std::system_error on failure
std::vector<network_interface> enumerate_interfaces();

// Non-throwing overload -- sets ec on failure
std::vector<network_interface> enumerate_interfaces(std::error_code &ec);
```

Cross-platform: uses `getifaddrs` on Linux and macOS, `GetAdaptersAddresses`
on Windows. The address bytes are in network byte order; `inet_ntop` formats them as
text.

### Example: list all interfaces

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    for (const auto &iface : mdnspp::enumerate_interfaces())
    {
        std::cout << iface.name
                  << "  index=" << iface.index
                  << "  up=" << iface.is_up
                  << "  loopback=" << iface.is_loopback
                  << std::endl;
        for (const mdnspp::ip_network &net : iface.addresses)
            std::cout << "  "
                      << (net.address.family == mdnspp::address_family::ipv4 ? "IPv4" : "IPv6")
                      << " /" << int{net.prefix_length}
                      << std::endl;
    }
}
```

## Usage examples

### Binding to a specific NIC

Name the interface directly &mdash; the address of the socket family is resolved
at socket open:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <iostream>

int main()
{
    mdnspp::socket_options opts{.interface_name = "eth0"};

    mdnspp::context ctx;
    auto info = mdnspp::service_info::make("MyApp", "_http._tcp", 8080);
    if (!info.has_value())
        return 1;

    // The server announces the A/AAAA addresses of the bound interface
    // (service_info::make() leaves them unset; see service_info docs).
    mdnspp::service_server srv{ctx, std::move(*info), {}, opts};
    srv.async_start();
    ctx.run();
}
```

Alternatively, enumerate interfaces and pass the chosen one's index:

```cpp
auto ifaces = mdnspp::enumerate_interfaces();

// Pick the first non-loopback interface that is up and has an IPv4 address
auto has_ipv4 = [](const mdnspp::network_interface &iface) {
    return std::ranges::any_of(iface.addresses, [](const mdnspp::ip_network &net) {
        return net.address.family == mdnspp::address_family::ipv4;
    });
};
auto it = std::ranges::find_if(ifaces, [&](const auto &iface) {
    return iface.is_up && !iface.is_loopback && has_ipv4(iface);
});

if (it == ifaces.end())
    return 1;

mdnspp::socket_options opts{.interface_index = it->index};
```

### Setting the send TTL

RFC 6762 Section 11 says responses SHOULD be sent with IP TTL 255. With
`multicast_ttl` unset, the library sends with 255. You can also set it
explicitly:

```cpp
mdnspp::socket_options opts{.multicast_ttl = 255};
```

Unicast datagrams (for example replies to a QU question or to a legacy querier) leave with
the same value: the native and Asio sockets set `IP_TTL` / `IPV6_UNICAST_HOPS` alongside
`IP_MULTICAST_TTL` / `IPV6_MULTICAST_HOPS`. RFC 6762 Section 11:

> All Multicast DNS responses (including responses sent via unicast) SHOULD be sent with IP TTL set to 255.  This is recommended to provide backwards-compatibility with older Multicast DNS queriers (implementing a draft version of this document, posted in February 2004) that check the IP TTL on reception to determine whether the packet originated on the local link.  These older queriers discard all packets with TTLs other than 255.

Without it a unicast reply would leave with the operating system default (64 on Linux) and
a peer whose `receive_ttl_minimum` is 255 would drop it.

### Using socket_options with default_policy convenience aliases

All default_policy convenience aliases (`mdnspp::observer`, `mdnspp::querier`,
`mdnspp::service_discovery`, `mdnspp::service_server`) accept `socket_options`
as an optional constructor parameter:

```cpp
mdnspp::context ctx;
mdnspp::socket_options opts{.interface_address = "192.168.1.10"};

mdnspp::observer obs{ctx, mdnspp::observer_options{.on_record = on_record}, opts};
mdnspp::querier  q{ctx, {}, opts};
```

### Using socket_options with asio_policy

The `basic_*` templates accept `socket_options` the same way:

```cpp
asio::io_context io;
mdnspp::socket_options opts{.interface_address = "192.168.1.10"};

mdnspp::basic_observer<mdnspp::asio_policy> obs{io, mdnspp::observer_options{.on_record = on_record}, opts};
```

## Multicast Group and Port

The `multicast_group` field controls which multicast address and port mdnspp
joins and transmits on. The default is the IANA-assigned mDNS group
`224.0.0.251:5353` (IPv4) or `[ff02::fb]:5353` (IPv6, Link-Local).

Changing the group lets you create isolated namespaces &mdash; for example, a test
environment that does not interfere with production mDNS traffic on the same
segment.

The address must be an IPv4 multicast address (`224.0.0.0/4`) or an IPv6
multicast address (`ff00::/8`). Any other address, including an empty or
malformed one, fails construction of the native and Asio sockets with
`std::errc::invalid_argument` (the throwing constructors throw
`std::system_error`).

A socket for an IPv6 group is IPv6-only: the native and Asio sockets set
`IPV6_V6ONLY` before binding, so an IPv6 socket never receives IPv4 datagrams
sent to its port (as IPv4-mapped senders) on dual-stack systems. If the option
cannot be set, construction fails with the `setsockopt` error.

### Recommended address ranges

**IPv4 &mdash; isolated namespaces**

| Range | Scope | Notes |
|-------|-------|-------|
| `239.0.0.0/8` | Organization-Local (RFC 2365) | Preferred for private mDNS namespaces; routers do not forward this range by default |
| `224.0.0.251` | Link-Local (IANA mDNS) | Standard mDNS group; use only for RFC 6762 production traffic |

**IPv6 &mdash; isolated namespaces**

| Range | Scope | Notes |
|-------|-------|-------|
| `ff02::fb` | Link-Local | Standard mDNS group (IANA assigned) |
| `ff05::/16` | Site-Local | Contained within a site; not forwarded by border routers |
| `ff08::/16` | Organization-Local | Contained within an organisation |

### Port isolation

Custom ports (e.g. `5354`) require **all** participants to use the same port.
A node using `5354` and a node using the default `5353` cannot see each other
even if they share the same multicast group address.

### Example: custom group via designated initializer

```cpp
#include <mdnspp/defaults.h>

int main()
{
    mdnspp::context ctx;

    // Use an organisation-local group on a non-standard port.
    // All peers must be configured identically.
    mdnspp::socket_options opts{
        .multicast_group = {"239.1.2.3", 5354},
    };

    mdnspp::service_discovery sd{ctx, {}, opts};
    sd.async_discover("_myapp._tcp.local.", [&ctx](auto ec, auto) { ctx.stop(); });
    ctx.run();
}
```

For IPv6, substitute an IPv6 address in the endpoint:

```cpp
mdnspp::socket_options opts{
    .multicast_group = {"ff05::1234", 5354},
};
```

mdnspp auto-detects whether the address is IPv4 or IPv6 and configures the
socket accordingly.

## Receive-side TTL extraction

No RFC rule requires a receive-side TTL check; RFC 6762 §11 has only the
send-side SHOULD for responses. mdnspp offers the check as hardening, applied
to responses only: queries are never dropped for their TTL. The sockets
populate the `recv_metadata::ttl` field it reads.

### Socket option configuration

The following `setsockopt` calls are made during socket construction when TTL
extraction is enabled:

| Platform | Option | Purpose |
|----------|--------|---------|
| Linux (IPv4) | `IP_RECVTTL` | Deliver IP TTL as ancillary data in `recvmsg` |
| Linux (IPv6) | `IPV6_RECVHOPLIMIT` | Deliver IPv6 hop limit as ancillary data |
| Linux / macOS / Windows | `IP_PKTINFO` | Deliver receiving interface index and destination address as ancillary data |
| Linux / macOS (IPv6) | `IPV6_RECVPKTINFO` | Deliver IPv6 receiving interface index and destination address |
| Windows (IPv4) | `IP_RECVTTL`, `WSARecvMsg` obtained via `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` | WSARecvMsg ancillary TTL |
| Windows (IPv6) | `IPV6_HOPLIMIT`, `IPV6_PKTINFO` | WSARecvMsg ancillary hop limit, interface index and destination (Windows has no `IPV6_RECV*` options) |

### Platform matrix

| Platform | default_socket | asio_socket |
|----------|--------------|------------|
| Linux | Real TTL via `recvmsg` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` | Real TTL via `async_wait` + `recvmsg` on `native_handle()`; same ancillary data path |
| macOS | Real TTL via `recvmsg` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` | Real TTL via `async_wait` + `recvmsg` on `native_handle()`; same ancillary data path |
| Windows | Real TTL via `WSARecvMsg` + `IP_RECVTTL` | Real TTL via `WSARecvMsg` on `native_handle()`; same extension pointer approach |

When TTL extraction fails silently (setsockopt error, extension pointer
unavailable), the socket opens normally and `recv_metadata::ttl` is left as
`std::nullopt`. The `mdns_options::unknown_ttl_policy` field controls
whether such responses are accepted or rejected.

### Filtering configuration

TTL filtering is configured via `mdns_options`:

```cpp
mdns_options opts{
    .receive_ttl_minimum  = 255,                    // discard responses with TTL < 255
    .unknown_ttl_policy   = ttl_unknown_policy::accept, // accept when TTL unavailable
};
```

See [mdns_options](api/mdns_options.md) for all fields. For the rationale and
the RFC text on TTL 255, see [Receive-Side TTL](rfc/receive-ttl.md).
For the `recv_metadata` struct fields, see [recv_metadata](api/recv_metadata.md).

## Known limitations

### Receive-side filtering by the kernel

`IP_ADD_MEMBERSHIP` / `IPV6_JOIN_GROUP` with a specific interface controls
which interface joins the multicast group, but the kernel delivers multicast
arriving on the port to every socket bound to it, whichever interface each
socket joined on. The peers filter these packets themselves (see
[Receive interface attribution](#receive-interface-attribution)); a custom
socket without `interface_index()` gets no such filtering. Send-side binding
(`IP_MULTICAST_IF` / `IPV6_MULTICAST_IF`) works correctly.

### Windows multicast loopback semantics

The `IP_MULTICAST_LOOP` socket option has inverted default behavior on Windows
compared to POSIX systems. On POSIX, loopback is enabled by default; on
Windows, loopback is also enabled by default, but the underlying
implementation semantics differ. The `loopback_mode` enum abstracts this
difference -- use `loopback_mode::enabled` or `loopback_mode::disabled` and
the library applies the correct platform-specific value.

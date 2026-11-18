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
| `interface_address` | `std::string` | `""` (empty) | Address of the NIC to bind, in the family of `multicast_group.address` (see below). Empty string means `INADDR_ANY` (all interfaces). |
| `interface_name` | `std::optional<std::string>` | `std::nullopt` | OS interface name of the NIC to bind (e.g. `"eth0"`, `"en0"`). Resolved at socket open via `enumerate_interfaces()`. |
| `interface_index` | `std::optional<uint32_t>` | `std::nullopt` | OS interface index of the NIC to bind. Resolved at socket open via `enumerate_interfaces()`. |
| `multicast_group` | `endpoint` | `{"224.0.0.251", 5353}` | Multicast group address and port. Change this to isolate mDNS traffic to a custom namespace. |
| `multicast_loopback` | `loopback_mode` | `loopback_mode::enabled` | Whether multicast packets are looped back to the sending host. Enabled by default so that services and clients on the same machine can communicate. |
| `multicast_ttl` | `std::optional<std::uint8_t>` | `std::nullopt` | Multicast time-to-live. When `socket_options` is used, defaults to 255 per RFC 6762 Section 11. `std::nullopt` leaves the OS default. |

### Interface selection precedence and address family

When more than one of the binding fields is set, the precedence at socket
open is `interface_index` > `interface_name` > `interface_address`: a set
`interface_index` is resolved by index only, and an unmatched index fails
socket construction with `std::errc::invalid_argument` rather than falling
back to the name or address (the same applies to an unmatched
`interface_name`). An `interface_index` or `interface_name` is translated to
the matching interface's address via `enumerate_interfaces()` and then
follows the same code path as `interface_address`.

The family of `multicast_group.address` selects the socket family, and the
effective interface address must be of the same family: a dotted-decimal
IPv4 address for IPv4 sockets (applied through `IP_MULTICAST_IF` /
`IP_ADD_MEMBERSHIP`), or a colon-hex IPv6 address for IPv6 sockets
(translated internally to the owning interface's index for
`IPV6_MULTICAST_IF` / `IPV6_JOIN_GROUP`). A NIC selected by index or name
that has no address of the socket family fails with
`std::errc::invalid_argument`.

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
    std::string ipv4_address;
    std::string ipv6_address;
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
| `ipv4_address` | `std::string` | IPv4 address in dotted-decimal notation. Empty if the interface has no IPv4 address. |
| `ipv6_address` | `std::string` | IPv6 address in colon-hex notation. Empty if the interface has no IPv6 address. |
| `index` | `uint32_t` | OS interface index. |
| `is_loopback` | `bool` | `true` if this is the loopback interface (`lo`, `lo0`). |
| `is_up` | `bool` | `true` if the interface is currently up. |

## enumerate_interfaces()

Returns all network interfaces on the host. Two overloads are available:

```cpp
// Throwing overload -- throws std::system_error on failure
std::vector<network_interface> enumerate_interfaces();

// Non-throwing overload -- sets ec on failure
std::vector<network_interface> enumerate_interfaces(std::error_code &ec);
```

Cross-platform: uses `getifaddrs` on Linux and macOS, `GetAdaptersAddresses`
on Windows.

### Example: list all interfaces

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    for (const auto &iface : mdnspp::enumerate_interfaces())
    {
        std::cout << iface.name
                  << "  ipv4=" << iface.ipv4_address
                  << "  ipv6=" << iface.ipv6_address
                  << "  up=" << iface.is_up
                  << "  loopback=" << iface.is_loopback
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

Alternatively, enumerate interfaces and pass an address explicitly:

```cpp
auto ifaces = mdnspp::enumerate_interfaces();

// Pick the first non-loopback interface that is up and has an IPv4 address
auto it = std::ranges::find_if(ifaces, [](const auto &iface) {
    return iface.is_up && !iface.is_loopback && !iface.ipv4_address.empty();
});

if (it == ifaces.end())
    return 1;

mdnspp::socket_options opts{.interface_address = it->ipv4_address};
```

### Setting TTL for RFC 6762 compliance

RFC 6762 Section 11 requires a multicast TTL of 255 for mDNS. When
`socket_options` is used, the library defaults to 255. You can also set it
explicitly:

```cpp
mdnspp::socket_options opts{.multicast_ttl = 255};
```

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

RFC 6762 §11 requires that mDNS implementations verify the IP TTL of received
packets and discard those with a TTL below 255. mdnspp implements this via
the `recv_metadata::ttl` field populated by the socket implementation.

### Socket option configuration

The following `setsockopt` calls are made during socket construction when TTL
extraction is enabled:

| Platform | Option | Purpose |
|----------|--------|---------|
| Linux (IPv4) | `IP_RECVTTL` | Deliver IP TTL as ancillary data in `recvmsg` |
| Linux (IPv6) | `IPV6_RECVHOPLIMIT` | Deliver IPv6 hop limit as ancillary data |
| Linux / macOS | `IP_PKTINFO` / `IP_RECVIF` | Deliver receiving interface index as ancillary data |
| Windows (IPv4) | `IP_RECVTTL`, `WSARecvMsg` obtained via `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` | WSARecvMsg ancillary TTL |
| Windows (IPv6) | `IPV6_RECVHOPLIMIT` | WSARecvMsg ancillary hop limit |

### Platform matrix

| Platform | default_socket | asio_socket |
|----------|--------------|------------|
| Linux | Real TTL via `recvmsg` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` | Real TTL via `async_wait` + `recvmsg` on `native_handle()`; same ancillary data path |
| macOS | Real TTL via `recvmsg` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` | Real TTL via `async_wait` + `recvmsg` on `native_handle()`; same ancillary data path |
| Windows | Real TTL via `WSARecvMsg` + `IP_RECVTTL` | Real TTL via `WSARecvMsg` on `native_handle()`; same extension pointer approach |

When TTL extraction fails silently (setsockopt error, extension pointer
unavailable), the socket opens normally and `recv_metadata::ttl` is left as
`std::nullopt`. The `mdns_options::unknown_ttl_policy` field controls
whether such packets are accepted or rejected.

### Filtering configuration

TTL filtering is configured via `mdns_options`:

```cpp
mdns_options opts{
    .receive_ttl_minimum  = 255,                    // discard packets with TTL < 255
    .unknown_ttl_policy   = ttl_unknown_policy::accept, // accept when TTL unavailable
};
```

See [mdns_options](api/mdns_options.md) for all fields. For the full
RFC 6762 §11 compliance discussion, see [Receive-Side TTL](rfc/receive-ttl.md).
For the `recv_metadata` struct fields, see [recv_metadata](api/recv_metadata.md).

## Known limitations

### Linux receive-side filtering

On Linux, `IP_ADD_MEMBERSHIP` with a specific interface address controls which
interface the kernel uses for joining the multicast group, but it does not
fully isolate receive traffic. The kernel delivers multicast packets arriving
on port 5353 to all sockets bound to that port, regardless of which interface
each socket joined on. Send-side binding (`IP_MULTICAST_IF`) works correctly.

### Windows multicast loopback semantics

The `IP_MULTICAST_LOOP` socket option has inverted default behavior on Windows
compared to POSIX systems. On POSIX, loopback is enabled by default; on
Windows, loopback is also enabled by default, but the underlying
implementation semantics differ. The `loopback_mode` enum abstracts this
difference -- use `loopback_mode::enabled` or `loopback_mode::disabled` and
the library applies the correct platform-specific value.

# Socket Options

## Overview

`socket_options` lets you control which network interface mDNS operates on,
set the multicast TTL, and enable or disable multicast loopback. By default,
mdnspp binds to all interfaces (`INADDR_ANY`). When you need to isolate mDNS
traffic to a specific NIC -- for example on a multi-homed server or an
embedded device with separate management and data networks -- construct your
mdnspp types with a `socket_options` value.

**Headers:**

```cpp
#include <mdnspp/socket_options.h>
#include <mdnspp/network_interface.h>
```

Both headers are included transitively by `#include <mdnspp/defaults.h>`.

## socket_options struct

```cpp
namespace mdnspp {

enum class loopback_mode { enabled, disabled };

struct socket_options
{
    std::string interface_address{};
    endpoint multicast_group{"224.0.0.251", 5353};
    loopback_mode multicast_loopback{loopback_mode::enabled};
    std::optional<std::uint8_t> multicast_ttl{};
};

}
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `interface_address` | `std::string` | `""` (empty) | IPv4 address of the NIC to bind. Empty string means `INADDR_ANY` (all interfaces). |
| `multicast_group` | `endpoint` | `{"224.0.0.251", 5353}` | Multicast group address and port. Change this to isolate mDNS traffic to a custom namespace. |
| `multicast_loopback` | `loopback_mode` | `loopback_mode::enabled` | Whether multicast packets are looped back to the sending host. Enabled by default so that services and clients on the same machine can communicate. |
| `multicast_ttl` | `std::optional<std::uint8_t>` | `std::nullopt` | Multicast time-to-live. When `socket_options` is used, defaults to 255 per RFC 6762 Section 11. `std::nullopt` leaves the OS default. |

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
    unsigned int index{0};
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
| `index` | `unsigned int` | OS interface index. |
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
                  << "\n";
    }
}
```

## Usage examples

### Binding to a specific NIC

Enumerate interfaces, pick the one you want, and pass its address via
`socket_options`:

```cpp
#include <mdnspp/defaults.h>
#include <mdnspp/service_info.h>

#include <iostream>
#include <ranges>

int main()
{
    auto ifaces = mdnspp::enumerate_interfaces();

    // Pick the first non-loopback interface that is up and has an IPv4 address
    auto it = std::ranges::find_if(ifaces, [](const auto &iface) {
        return iface.is_up && !iface.is_loopback && !iface.ipv4_address.empty();
    });

    if (it == ifaces.end())
    {
        std::cerr << "no suitable interface found\n";
        return 1;
    }

    mdnspp::socket_options opts{.interface_address = it->ipv4_address};

    mdnspp::context ctx;
    mdnspp::service_info info{
        .service_name = "MyApp._http._tcp.local.",
        .service_type = "_http._tcp.local.",
        .hostname     = "myhost.local.",
        .port         = 8080,
        .address_ipv4 = it->ipv4_address,
    };

    mdnspp::service_server srv{ctx, std::move(info), {}, opts};
    srv.async_start();
    ctx.run();
}
```

### Setting TTL for RFC 6762 compliance

RFC 6762 Section 11 requires a multicast TTL of 255 for mDNS. When
`socket_options` is used, the library defaults to 255. You can also set it
explicitly:

```cpp
mdnspp::socket_options opts{.multicast_ttl = 255};
```

### Using socket_options with DefaultPolicy convenience aliases

All DefaultPolicy convenience aliases (`mdnspp::observer`, `mdnspp::querier`,
`mdnspp::service_discovery`, `mdnspp::service_server`) accept `socket_options`
as an optional constructor parameter:

```cpp
mdnspp::context ctx;
mdnspp::socket_options opts{.interface_address = "192.168.1.10"};

mdnspp::observer obs{ctx, mdnspp::observer_options{.on_record = on_record}, opts};
mdnspp::querier  q{ctx, {}, opts};
```

### Using socket_options with AsioPolicy

The `basic_*` templates accept `socket_options` the same way:

```cpp
asio::io_context io;
mdnspp::socket_options opts{.interface_address = "192.168.1.10"};

mdnspp::basic_observer<mdnspp::AsioPolicy> obs{io, mdnspp::observer_options{.on_record = on_record}, opts};
```

## Multicast Group and Port

The `multicast_group` field controls which multicast address and port mdnspp
joins and transmits on. The default is the IANA-assigned mDNS group
`224.0.0.251:5353` (IPv4) or `[ff02::fb]:5353` (IPv6, Link-Local).

Changing the group lets you create isolated namespaces -- for example, a test
environment that does not interfere with production mDNS traffic on the same
segment.

### Recommended address ranges

**IPv4 -- isolated namespaces**

| Range | Scope | Notes |
|-------|-------|-------|
| `239.0.0.0/8` | Organization-Local (RFC 2365) | Preferred for private mDNS namespaces; routers do not forward this range by default |
| `224.0.0.251` | Link-Local (IANA mDNS) | Standard mDNS group; use only for RFC 6762 production traffic |

**IPv6 -- isolated namespaces**

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

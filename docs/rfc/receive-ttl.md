# Receive-Side TTL Verification

RFC 6762 §11 requires that mDNS packets be received only from link-local senders —
that is, packets that have not been forwarded by a router. The mechanism is the IP
TTL (hop limit): a multicast packet sent with TTL=255 will have its hop count
decremented to 254 by any router that forwards it. A receiver that discards packets
with TTL below 255 is therefore guaranteed to see only link-local traffic.

Without this check, an attacker on a remote network could inject spoofed mDNS packets
and cause a resolver to accept false service announcements.

**RFC Reference:** RFC 6762 §11

## Example

Configure `receive_ttl_minimum` and `unknown_ttl_policy` via `mdns_options`:

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::mdns_options mdns_opts{
        .receive_ttl_minimum = 255,                                     // RFC 6762 §11 default
        .unknown_ttl_policy  = mdnspp::ttl_unknown_policy::accept,      // default: accept
    };

    mdnspp::monitor_options mon_opts{
        .on_found = [](const mdnspp::resolved_service &svc)
        {
            std::cout << "found: " << svc.instance_name << std::endl;
        },
    };

    // Pass mdns_opts when constructing a service_monitor
    mdnspp::service_monitor mon{ctx, std::move(mon_opts), {}, mdns_opts};

    mon.watch("_http._tcp.local.");
    mon.async_start();

    ctx.run();
}
```

Packets with TTL below `receive_ttl_minimum` are silently discarded before any callback
fires. The default value of 255 matches the RFC requirement. Setting `unknown_ttl_policy`
to `reject` also discards packets where TTL extraction failed at the socket level.

---

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Receive-side TTL threshold | `mdns_options::receive_ttl_minimum` (default 255) |
| Implemented | TTL extraction — Linux | `recvmsg()` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` |
| Implemented | TTL extraction — macOS | `recvmsg()` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` |
| Implemented | TTL extraction — Windows | `WSARecvMsg` via `SIO_GET_EXTENSION_FUNCTION_POINTER` |
| Implemented | Silent degradation on extraction failure | `recv_metadata::ttl = nullopt`; socket continues normally |
| Implemented | Policy for TTL-unknown packets | `mdns_options::unknown_ttl_policy` (`accept` / `reject`) |
| User choice | Policy selection | `ttl_unknown_policy::accept` is the default (backward-compatible) |

---

## In-Depth

### Why TTL=255 prevents spoofing

IPv4 TTL and IPv6 Hop Limit are decremented by every router that forwards a packet. A
packet transmitted from the local link segment always reaches its destination with the
original TTL intact. Any packet that has crossed at least one router arrives with TTL
at most 254.

By requiring `recv_metadata::ttl >= receive_ttl_minimum` (defaulting to 255), mdnspp
ensures that only link-local traffic is processed. Packets from remote networks are
silently discarded regardless of their mDNS content.

### Platform TTL extraction

TTL extraction is configured at socket construction time using platform socket options.

| Platform | default_socket | asio_socket |
|----------|--------------|------------|
| Linux | `recvmsg()` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` ancillary data; always available | `async_wait` + `recvmsg()` on `native_handle()`; same ancillary data path |
| macOS | `recvmsg()` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` ancillary data; always available | `async_wait` + `recvmsg()` on `native_handle()`; same ancillary data path |
| Windows | `WSARecvMsg` via `SIO_GET_EXTENSION_FUNCTION_POINTER`; `nullopt` if extension unavailable | `WSARecvMsg` on `native_handle()`; same extension pointer approach |

On POSIX systems, `IP_RECVTTL` is enabled with `setsockopt`. On Windows, the
`WSARecvMsg` function pointer is obtained once via `WSAIoctl` at socket construction and
stored per socket. Any failure in obtaining the pointer (e.g., on very old Windows
versions) results in silent degradation.

### Silent degradation

When TTL extraction fails at the socket level — or when the platform does not support it —
the socket continues to function normally. `recv_metadata::ttl` is left as `std::nullopt`
for every received packet. The application can detect this condition by checking whether
the field is populated or by observing `unknown_ttl_policy` behavior.

### ttl_unknown_policy

`ttl_unknown_policy::accept` (the default) forwards packets with `nullopt` TTL to all
handlers without restriction. This is the backward-compatible choice: on platforms that
do not support TTL extraction, all traffic is accepted.

`ttl_unknown_policy::reject` discards packets with `nullopt` TTL. This is appropriate
when strict RFC 6762 §11 compliance is required and the deployment target is known to
support TTL extraction on all platforms in use.

The policy is set via `mdns_options::unknown_ttl_policy` and applies to all sockets
constructed with those options.

### Interface index extraction

Alongside TTL, mdnspp extracts the receiving interface index into
`recv_metadata::recv_ifindex` using `IP_PKTINFO` (Linux / Windows) or `IP_RECVIF` with
`sockaddr_dl` (macOS). This field is used internally by `basic_nic_group` to populate
`resolved_service::source_interface`.

## See Also

- [recv_metadata](../api/recv_metadata.md) — struct fields, ttl_unknown_policy enum, platform matrix
- [mdns_options](../api/mdns_options.md) — `receive_ttl_minimum` and `unknown_ttl_policy` fields
- [socket-options](../socket-options.md) — socket construction and multicast group configuration

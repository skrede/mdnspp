# Receive-Side TTL Check

mdnspp can discard received **responses** whose IP TTL (IPv6 hop limit) is below a
threshold, `mdns_options::receive_ttl_minimum` (default 255). A multicast packet sent
with TTL 255 arrives with a lower TTL once a router has forwarded it, so the check
keeps responses that crossed a router out of the cache. Queries are never dropped for
their TTL.

No RFC rule requires this check. RFC 6762 has a single IP TTL rule, and it is a
send-side SHOULD for responses (RFC 6762 §11):

> All Multicast DNS responses (including responses sent via unicast) SHOULD be sent with IP TTL set to 255.  This is recommended to provide backwards-compatibility with older Multicast DNS queriers (implementing a draft version of this document, posted in February 2004) that check the IP TTL on reception to determine whether the packet originated on the local link.  These older queriers discard all packets with TTLs other than 255.

The receive check is a hardening option in the spirit of those older queriers. The
receive-side MUST of RFC 6762 §11 is that a querier accepts only responses from the
local link, and the RFC decides that by destination address and source subnet, not by
IP TTL.

Queries are exempt because one-shot resolvers (RFC 6762 §5.1) often send with the
operating system's default multicast TTL, commonly 1, and RFC 6762 §6.7 requires a
reply to them:

> If the source UDP port in a received Multicast DNS query is not port 5353, this indicates that the querier originating the query is a simple resolver such as described in Section 5.1, "One-Shot Multicast DNS Queries", which does not fully implement all of Multicast DNS. In this case, the Multicast DNS responder MUST send a UDP response directly back to the querier, via unicast, to the query packet's source IP address and port.

With default options a service server therefore answers a legacy query sent with TTL 1.

**RFC Reference:** RFC 6762 §11 (send-side TTL), RFC 6762 §6.7 (legacy queries)

## Example

Configure `receive_ttl_minimum` and `unknown_ttl_policy` via `mdns_options`:

```cpp
#include <mdnspp/defaults.h>

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::mdns_options mdns_opts{
        .receive_ttl_minimum = 255,                                     // default; responses only
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

Responses with a TTL below `receive_ttl_minimum` are silently discarded before any callback
fires. Setting `unknown_ttl_policy` to `reject` also discards responses whose TTL could not
be extracted at the socket level. Queries pass both checks whatever their TTL.

---

## Compliance Status

| Status | Aspect | Notes |
|--------|--------|-------|
| Implemented | Receive-side TTL threshold | `mdns_options::receive_ttl_minimum` (default 255); responses only, not an RFC requirement |
| Implemented | TTL extraction — Linux | `recvmsg()` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` |
| Implemented | TTL extraction — macOS | `recvmsg()` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT` |
| Implemented | TTL extraction — Windows | `WSARecvMsg` via `SIO_GET_EXTENSION_FUNCTION_POINTER` |
| Implemented | Silent degradation on extraction failure | `recv_metadata::ttl = nullopt`; socket continues normally |
| Implemented | Policy for TTL-unknown responses | `mdns_options::unknown_ttl_policy` (`accept` / `reject`); queries are never dropped |
| User choice | Policy selection | `ttl_unknown_policy::accept` is the default (backward-compatible) |

---

## In-Depth

### What the threshold filters

IPv4 TTL and IPv6 Hop Limit are decremented by every router that forwards a packet. A
packet sent with TTL 255 from the local link arrives with TTL 255; one that has crossed
at least one router arrives with TTL at most 254.

By requiring `recv_metadata::ttl >= receive_ttl_minimum` (default 255) of every response,
mdnspp drops forwarded responses and responses from senders that do not follow the
send-side SHOULD of RFC 6762 §11. The check runs in the receive path of every peer, after
the header checks and the source port check and before any response is parsed. A query
skips it and reaches the service server whatever its TTL.

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

`ttl_unknown_policy::accept` (the default) passes responses with `nullopt` TTL to all
handlers without restriction. This is the backward-compatible choice: on platforms that
do not support TTL extraction, all responses are accepted.

`ttl_unknown_policy::reject` discards responses with `nullopt` TTL. Use it only where the
TTL check is wanted as hardening and the deployment target is known to support TTL
extraction on all platforms in use. Queries with `nullopt` TTL are still answered.

The policy is set via `mdns_options::unknown_ttl_policy` and applies to every peer
constructed with those options.

### Interface index extraction

Alongside TTL, mdnspp extracts the receiving interface index into
`recv_metadata::recv_ifindex` using `IP_PKTINFO` (IPv4) and `IPV6_PKTINFO` (IPv6) on
Linux, macOS and Windows. This field is used internally by `basic_nic_group` to populate
`resolved_service::source_interface`.

## See Also

- [recv_metadata](../api/recv_metadata.md) — struct fields, ttl_unknown_policy enum, platform matrix
- [mdns_options](../api/mdns_options.md) — `receive_ttl_minimum` and `unknown_ttl_policy` fields
- [socket-options](../socket-options.md) — socket construction and multicast group configuration

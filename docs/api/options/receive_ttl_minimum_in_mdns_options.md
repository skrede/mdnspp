# receive_ttl_minimum in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `uint32_t` |
| **Default** | `255` |
| **One-liner** | Minimum IP TTL (hop limit) for received mDNS responses; queries are exempt |

## What

`receive_ttl_minimum` is a receive-side hardening check on incoming mDNS **responses**. Every received UDP packet carries an IP TTL (IPv4) or hop limit (IPv6) in its IP header. The stack compares this value with `receive_ttl_minimum` and silently discards any response whose IP TTL is below the threshold.

Queries are never dropped for their TTL. One-shot resolvers (RFC 6762 §5.1) often send with the operating system's default multicast TTL, commonly 1, and RFC 6762 §6.7 requires a reply to them, so a service server answers a legacy query whatever its TTL.

The value 255 is the IP TTL a packet has when it leaves a sender that follows RFC 6762 §11, which says responses SHOULD be sent with IP TTL 255. Because each router hop decrements the TTL by 1, a response forwarded by at least one router arrives with a TTL of 254 or lower, and the default threshold discards it.

## Why

No RFC rule requires a receive TTL check. RFC 6762 §11 has only the send-side SHOULD:

> All Multicast DNS responses (including responses sent via unicast) SHOULD be sent with IP TTL set to 255.  This is recommended to provide backwards-compatibility with older Multicast DNS queriers (implementing a draft version of this document, posted in February 2004) that check the IP TTL on reception to determine whether the packet originated on the local link.  These older queriers discard all packets with TTLs other than 255.

The receive-side MUST of RFC 6762 §11 is that a querier accepts only responses from the local link, decided by destination address and source subnet. The default of 255 is kept as hardening: it drops forwarded responses cheaply, before they are parsed.

Lower the value for a deployment where mDNS responses are deliberately forwarded across routers (a debugging setup, a tunnelled mDNS proxy, an experimental multi-hop discovery system), or to interoperate with responders that do not send with TTL 255.

## Danger

Reducing below 255 accepts responses forwarded by routers:

1. **Cross-segment spoofing**: a host on a remote subnet whose multicast is forwarded onto the link can forge responses that appear legitimate to your querier, injecting false service records into the local cache.
2. **Cache poisoning via forwarded traffic**: a misconfigured router that forwards multicast delivers responses from distant segments, and those responses are processed as if they came from the local link.

Lowering the threshold is a deliberate trade-off that the deployment context must justify; avoid it on networks with untrusted segments.

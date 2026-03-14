# receive_ttl_minimum in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `uint32_t` |
| **Default** | `255` |
| **One-liner** | Minimum IP TTL (hop limit) for received mDNS packets |

## What

`receive_ttl_minimum` enforces link-local scoping on incoming mDNS packets (RFC 6762 §11). Every received UDP packet carries an IP TTL (IPv4) or hop limit (IPv6) in its IP header. The stack checks this value against `receive_ttl_minimum` and silently discards any packet where the IP TTL is below the threshold.

The value 255 is the IP TTL a packet has when it leaves the sender's network interface. Because each router hop decrements the TTL by 1, any packet that has been forwarded by at least one router will arrive with a TTL of 254 or lower. Setting `receive_ttl_minimum` to 255 therefore enforces that only packets originating on the same link are accepted — the defining characteristic of link-local-only reception.

## Why

The default of 255 is mandatory for RFC-compliant mDNS operation. The RFC requires link-local scoping to prevent cross-segment spoofing and avoid the multicast scope leaking through routers.

The only reason to consider lowering this value is in a custom non-standard deployment where mDNS-like packets are deliberately forwarded across routers (e.g., a debugging setup, a tunnelled mDNS proxy, or an experimental multi-hop service discovery system). Such deployments are outside the RFC's scope and should be considered non-standard.

## Danger

Reducing below 255 allows packets forwarded by routers. This violates the mDNS link-local scoping requirement defined in RFC 6762 §11 and enables two distinct security risks:

1. **Cross-segment spoofing** — a malicious host on a remote subnet can forge mDNS responses that appear legitimate to your querier, injecting false service records into the local cache.
2. **Cache poisoning via forwarded traffic** — a misconfigured router that forwards multicast will deliver packets from distant segments; those packets will be accepted and processed as if they came from the local link.

Setting `receive_ttl_minimum` to any value below 255 should be treated as a deliberate security trade-off that must be justified by the specific deployment context. It must never be lowered in production deployments connected to untrusted networks.

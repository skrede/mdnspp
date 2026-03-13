# max_query_payload in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `std::size_t` |
| **Default** | `1472` bytes |
| **One-liner** | Maximum UDP payload before a query must be split into TC continuation packets |

## What

`max_query_payload` is the UDP payload size threshold at which the query builder switches from a single packet to a TC (truncation) split (RFC 6762 §6). When the serialised query — questions plus known-answer section — exceeds this limit, the TC bit is set and the overflow known answers are sent in one or more continuation packets.

The default of 1472 bytes matches the Ethernet MTU of 1500 bytes minus 20 bytes for the IPv4 header and 8 bytes for the UDP header. This is the largest payload that fits in a single Ethernet frame without IP fragmentation.

## Why

The default is correct for Ethernet-connected hosts. Reasons to reduce it:

- **Lower-MTU links** — IEEE 802.11 with A-MSDU or A-MPDU aggregation overhead effectively reduces the usable payload below 1472 bytes on some access points. On such links, setting `max_query_payload` to 1400 or 1450 bytes prevents silent IP fragmentation.
- **VPN or tunnel overhead** — encapsulation adds bytes to each packet. If the underlay MTU is 1500 bytes and the tunnel adds 40 bytes of headers, the effective payload limit for the overlay is closer to 1432 bytes.
- **IPv6** — IPv6 headers are 40 bytes (vs 20 for IPv4), reducing the available UDP payload to 1452 bytes on a standard Ethernet link. If using IPv6, set `max_query_payload` to 1452 to match.

Reasons to increase it (rare):

- **Jumbo frames** — on networks where jumbo frames (9000-byte MTU) are enabled end-to-end, increasing `max_query_payload` to 8972 reduces TC splitting frequency for large known-answer lists.

## Danger

Reducing forces earlier TC splits, increasing packet count. More packets means more multicast overhead per query and more continuation assembly work on all receivers. On a network with many queriers, frequent TC splits can increase the ambient multicast load substantially.

Increasing risks fragmentation on paths with smaller MTUs. A 1600-byte UDP packet must be fragmented by IP on a 1500-byte MTU link. IP-fragmented mDNS packets may be silently dropped by firewalls, access points, or network switches that block IP fragments in multicast traffic. The result is that large known-answer lists are silently lost — from the querier's perspective the query was sent, but no suppression occurs.

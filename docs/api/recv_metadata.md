# recv_metadata

Metadata carried with each received mDNS packet. Populated by the socket implementation
and forwarded through the receive loop to packet handlers.

## Header

```cpp
#include <mdnspp/policy.h>
```

---

## recv_metadata

```cpp
struct recv_metadata {
    endpoint                  sender;
    std::optional<uint8_t>    ttl;
    uint32_t                  recv_ifindex{0};
    std::optional<ip_address> destination;
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sender` | `endpoint` | — | Source address and port of the received packet. A link-local IPv6 sender carries an RFC 4007 numeric zone suffix (`fe80::1%3`, the index of the receiving interface); other senders carry no zone. |
| `ttl` | `std::optional<uint8_t>` | `std::nullopt` | IP hop limit (TTL) of the received packet. `nullopt` when the platform or socket type could not extract the TTL. |
| `recv_ifindex` | `uint32_t` | `0` | Interface index on which the packet arrived. Populated from `IP_PKTINFO` for IPv4 (Linux, macOS, Windows) and from `IPV6_PKTINFO` for IPv6 (on macOS through the RFC 3542 options). `0` when not populated or when the control data was truncated. |
| `destination` | `std::optional<ip_address>` | `std::nullopt` | The destination address from the IP header of the received packet: the multicast group for a multicast datagram, the local unicast address for a unicast one. Read from the same `IP_PKTINFO` (`ipi_addr`) and `IPV6_PKTINFO` (`ipi6_addr`) control messages as `recv_ifindex`. `nullopt` when the platform reports no destination or when the control data was truncated, in which case `recv_ifindex` and `ttl` are unknown too. See [ip_address](ip_address.md). |

`recv_metadata` is passed by const reference to the `socket_like::async_receive` handler
(signature `void(std::error_code, const recv_metadata &, std::span<std::byte>)`, error
code first; on error the metadata is empty) and flows through the receive loop. The
reference, like the data span, is valid only during the handler call: the default context
fills one `recv_metadata` and one receive buffer per dispatch nesting level, so a handler that
polls its context re-entrantly keeps its own data and metadata for the whole call, and the asio
socket fills one `recv_metadata` per socket. A handler that keeps the sender copies it. It is
not directly accessible from `monitor_options`,
`observer_options`, or other public callback APIs — it is consumed internally to apply
`receive_ttl_minimum` filtering to responses, to apply the local-link test, and to populate
`resolved_service::source_interface`.

**Local-link test (RFC 6762 §11, §5.5).** Every peer type uses `destination`, `sender` and
`recv_ifindex` to decide whether a packet came from the local link:

- A packet whose `destination` is a multicast address is on-link, whatever its source.
- A response whose `destination` is a unicast address passes only if the `sender` address lies
  in an on-link prefix of the receiving interface (`recv_ifindex`, or every interface when it is
  `0`) or equals an address of any local interface. A query sent to a unicast address passes on
  the same condition.
- When `destination` is `nullopt`, a response gets the same source test, because the gate cannot
  tell whether it was sent to the group or to this host. On such a platform an on-link unicast
  response is accepted, and a multicast response from a source outside every on-link prefix is
  dropped. A query of unknown destination is always kept, so legacy queriers get their reply.

The interface prefixes come from `enumerate_interfaces`, read on first use and re-read on a
miss at most once per second. Dropped packets are discarded silently. In-process transports
are exempt (see [inproc-bus](../inproc-bus.md)).

The zone on a link-local IPv6 `sender` lets a reply sent to `sender` leave through the
interface the packet arrived on; destination text also accepts an interface-name zone
(`fe80::1%eth0`), and an empty or unknown zone is rejected. A destination that is neither
IPv4 nor IPv6 text makes `send(dest, data, ec)` report `std::errc::invalid_argument` and the
throwing `send(dest, data)` throw `std::system_error` with that code; nothing is sent.

---

## ttl_unknown_policy

Policy applied to responses where the IP TTL could not be extracted. Queries are never dropped for their TTL.

```cpp
enum class ttl_unknown_policy { accept, reject };
```

| Value | Behavior |
|-------|----------|
| `accept` (default) | Responses with `recv_metadata::ttl == nullopt` are accepted and processed normally. Backward-compatible with platforms or socket configurations that do not support TTL extraction. |
| `reject` | Responses with `recv_metadata::ttl == nullopt` are silently discarded. Enforces the TTL check even when extraction fails. |

Set via `mdns_options::unknown_ttl_policy`:

```cpp
mdnspp::mdns_options opts{
    .receive_ttl_minimum  = 255,
    .unknown_ttl_policy   = mdnspp::ttl_unknown_policy::reject,
};
```

See [mdns_options](mdns_options.md) for the full options struct.

---

## Receive Metadata Platform Matrix

TTL, interface index and destination are enabled when the socket is constructed with
`setsockopt`. Failure is silent: the socket opens normally and the affected fields are left
unknown (`ttl == nullopt`, `recv_ifindex == 0`, `destination == nullopt`). The default and
asio sockets read the same control messages through one shared parser: `default_socket`
calls `recvmsg()` (`WSARecvMsg` on Windows, obtained via `SIO_GET_EXTENSION_FUNCTION_POINTER`),
and `asio_socket` waits with `async_wait` and makes the same call on `native_handle()`.

| Platform | Enabling options | `ttl` source | `recv_ifindex` and `destination` source | Status |
|----------|------------------|--------------|------------------------------------------|--------|
| Linux | `IP_RECVTTL`, `IP_PKTINFO`; `IPV6_RECVHOPLIMIT`, `IPV6_RECVPKTINFO` | `IP_TTL` (int); `IPV6_HOPLIMIT` | `in_pktinfo` `ipi_ifindex` / `ipi_addr`; `in6_pktinfo` `ipi6_ifindex` / `ipi6_addr` | verified by the receive metadata tests |
| macOS | `IP_RECVTTL`, `IP_PKTINFO`; `IPV6_RECVHOPLIMIT`, `IPV6_RECVPKTINFO` (RFC 3542 options, enabled by `__APPLE_USE_RFC_3542`) | `IP_RECVTTL` (one byte); `IPV6_HOPLIMIT` | `in_pktinfo` `ipi_ifindex` / `ipi_addr`; `in6_pktinfo` `ipi6_ifindex` / `ipi6_addr` | implemented, not yet confirmed by a hosted macOS run |
| Windows | `IP_RECVTTL`, `IP_PKTINFO`; `IPV6_HOPLIMIT`, `IPV6_PKTINFO` (Windows has no `IPV6_RECV*` options) | `IP_TTL` or `IP_RECVTTL` (the type is undocumented, both are read); `IPV6_HOPLIMIT` | `IN_PKTINFO` `ipi_ifindex` / `ipi_addr`; `IN6_PKTINFO` `ipi6_ifindex` / `ipi6_addr` | implemented, not yet confirmed by a hosted Windows run |

For a multicast datagram `destination` is the group; for a unicast datagram it is the local
address the datagram was sent to. On Windows systems without `WSARecvMsg` the socket falls back
to `recvfrom()`, and every field except `sender` is unknown. `unknown_ttl_policy` governs
whether responses without a TTL are accepted or rejected.

Each control message is read only up to its payload length; a payload shorter than the
option's type is ignored. When the kernel reports that the control data was truncated
(`MSG_CTRUNC`), the packet carries `ttl == nullopt`, `recv_ifindex == 0` and
`destination == nullopt` rather than partial metadata, and `unknown_ttl_policy` then governs it like any other packet without a TTL (responses only).

No RFC rule requires a receive TTL check; RFC 6762 §11 has only the send-side SHOULD that
responses carry IP TTL 255. For the rationale of the response-only check, see
[docs/rfc/receive-ttl.md](../rfc/receive-ttl.md).

---

## See Also

- [rfc/receive-ttl](../rfc/receive-ttl.md) — receive-side TTL check on responses, and what RFC 6762 §11 requires
- [mdns_options](mdns_options.md) — `receive_ttl_minimum` and `unknown_ttl_policy` fields
- [policies](../policies.md) — how `recv_metadata` flows through the `socket_like` concept
- [resolved_service](resolved_service.md) — `source_interface` field populated from `recv_ifindex`
- [ip_address](ip_address.md) — the address type of `destination`

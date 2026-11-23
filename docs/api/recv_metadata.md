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
| `recv_ifindex` | `uint32_t` | `0` | Interface index on which the packet arrived. Populated from `IP_PKTINFO` for IPv4 (Linux, macOS, Windows; `IP_RECVIF` with `sockaddr_dl` where `IP_PKTINFO` is unavailable) and from `IPV6_PKTINFO` for IPv6 (on macOS through the RFC 3542 options). `0` when not populated or when the control data was truncated. |
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
`receive_ttl_minimum` filtering and to populate `resolved_service::source_interface`.

The zone on a link-local IPv6 `sender` lets a reply sent to `sender` leave through the
interface the packet arrived on; destination text also accepts an interface-name zone
(`fe80::1%eth0`), and an empty or unknown zone is rejected. A destination that is neither
IPv4 nor IPv6 text makes `send(dest, data, ec)` report `std::errc::invalid_argument` and the
throwing `send(dest, data)` throw `std::system_error` with that code; nothing is sent.

---

## ttl_unknown_policy

Policy applied to packets where the IP TTL could not be extracted.

```cpp
enum class ttl_unknown_policy { accept, reject };
```

| Value | Behavior |
|-------|----------|
| `accept` (default) | Packets with `recv_metadata::ttl == nullopt` are accepted and processed normally. Backward-compatible with platforms or socket configurations that do not support TTL extraction. |
| `reject` | Packets with `recv_metadata::ttl == nullopt` are silently discarded. Enforces strict TTL checking even when extraction fails. |

Set via `mdns_options::unknown_ttl_policy`:

```cpp
mdnspp::mdns_options opts{
    .receive_ttl_minimum  = 255,
    .unknown_ttl_policy   = mdnspp::ttl_unknown_policy::reject,
};
```

See [mdns_options](mdns_options.md) for the full options struct.

---

## TTL Extraction Platform Matrix

TTL extraction is configured when the socket is constructed (via `IP_RECVTTL` /
`IPV6_RECVHOPLIMIT` `setsockopt` or `WSAIoctl`). Failure is silent: the socket opens
normally and `recv_metadata::ttl` is left as `nullopt`.

| Platform | default_socket | asio_socket |
|----------|--------------|------------|
| Linux | `recvmsg()` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT`; always available when socket opens | `async_wait` + `recvmsg()` on `native_handle()`; same ancillary data path |
| macOS | `recvmsg()` + `IP_RECVTTL` (the TTL arrives as a one-byte `IP_RECVTTL` payload) / `IPV6_RECVHOPLIMIT` (RFC 3542 options, enabled by `__APPLE_USE_RFC_3542`); always available when socket opens | `async_wait` + `recvmsg()` on `native_handle()`; same ancillary data path |
| Windows | `WSARecvMsg` via `SIO_GET_EXTENSION_FUNCTION_POINTER`; `nullopt` on systems where the extension is unavailable (pre-Vista) | `WSARecvMsg` on `native_handle()`; same extension pointer approach |

On all platforms, TTL extraction failure results in silent degradation: the socket
continues to function and `recv_metadata::ttl` is `nullopt` for every received packet.
`unknown_ttl_policy` governs whether those packets are accepted or rejected.

Each control message is read only up to its payload length; a payload shorter than the
option's type is ignored. When the kernel reports that the control data was truncated
(`MSG_CTRUNC`), the packet carries `ttl == nullopt`, `recv_ifindex == 0` and
`destination == nullopt` rather than partial metadata, and `unknown_ttl_policy` then governs it like any other packet without a TTL.

For the RFC rationale for receive-side TTL enforcement, see
[docs/rfc/receive-ttl.md](../rfc/receive-ttl.md).

---

## See Also

- [rfc/receive-ttl](../rfc/receive-ttl.md) — RFC 6762 §11 receive-side TTL verification
- [mdns_options](mdns_options.md) — `receive_ttl_minimum` and `unknown_ttl_policy` fields
- [policies](../policies.md) — how `recv_metadata` flows through the `socket_like` concept
- [resolved_service](resolved_service.md) — `source_interface` field populated from `recv_ifindex`
- [ip_address](ip_address.md) — the address type of `destination`

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
    endpoint              sender;
    std::optional<uint8_t> ttl;
    uint32_t              recv_ifindex{0};
};
```

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `sender` | `endpoint` | — | Source address and port of the received packet. |
| `ttl` | `std::optional<uint8_t>` | `std::nullopt` | IP hop limit (TTL) of the received packet. `nullopt` when the platform or socket type could not extract the TTL. |
| `recv_ifindex` | `uint32_t` | `0` | Interface index on which the packet arrived. Populated from `IP_PKTINFO` (Linux/Windows) or `IP_RECVIF` with `sockaddr_dl` (macOS). `0` when not populated. |

`recv_metadata` is passed by const reference to the `socket_like::async_receive` handler
(signature `void(std::error_code, const recv_metadata &, std::span<std::byte>)`, error
code first; on error the metadata is empty) and flows through the receive loop. It is
not directly accessible from `monitor_options`,
`observer_options`, or other public callback APIs — it is consumed internally to apply
`receive_ttl_minimum` filtering and to populate `resolved_service::source_interface`.

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
| macOS | `recvmsg()` + `IP_RECVTTL` / `IPV6_RECVHOPLIMIT`; always available when socket opens | `async_wait` + `recvmsg()` on `native_handle()`; same ancillary data path |
| Windows | `WSARecvMsg` via `SIO_GET_EXTENSION_FUNCTION_POINTER`; `nullopt` on systems where the extension is unavailable (pre-Vista) | `WSARecvMsg` on `native_handle()`; same extension pointer approach |

On all platforms, TTL extraction failure results in silent degradation: the socket
continues to function and `recv_metadata::ttl` is `nullopt` for every received packet.
`unknown_ttl_policy` governs whether those packets are accepted or rejected.

For the RFC rationale for receive-side TTL enforcement, see
[docs/rfc/receive-ttl.md](../rfc/receive-ttl.md).

---

## See Also

- [rfc/receive-ttl](../rfc/receive-ttl.md) — RFC 6762 §11 receive-side TTL verification
- [mdns_options](mdns_options.md) — `receive_ttl_minimum` and `unknown_ttl_policy` fields
- [policies](../policies.md) — how `recv_metadata` flows through the `socket_like` concept
- [resolved_service](resolved_service.md) — `source_interface` field populated from `recv_ifindex`

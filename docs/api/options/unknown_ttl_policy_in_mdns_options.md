# unknown_ttl_policy in mdns_options

| Attribute | Value |
|-----------|-------|
| **Type** | `ttl_unknown_policy` (enum: `accept`, `reject`) |
| **Default** | `ttl_unknown_policy::accept` |
| **One-liner** | Disposition for received responses whose IP TTL could not be extracted; queries are exempt |

## What

`unknown_ttl_policy` decides what happens to received responses whose IP TTL (IPv4) or hop limit (IPv6) is unavailable, i.e. `recv_metadata::ttl == std::nullopt`. It complements [`receive_ttl_minimum`](receive_ttl_minimum_in_mdns_options.md): that field compares against the extracted TTL; this field handles the case where there is no TTL to compare. Like `receive_ttl_minimum`, it applies to responses only: a query is never dropped for its TTL, known or unknown.

The TTL is extracted natively by `default_socket` and `asio_socket` on Linux, macOS (`recvmsg` ancillary data via `IP_RECVTTL` / `IPV6_RECVHOPLIMIT`), and Windows (`WSARecvMsg`). It is `std::nullopt` when the transport cannot supply it: custom policy sockets that do not populate `recv_metadata::ttl`, the in-process bus (`mdnspp::inproc`), and Windows systems where the `WSARecvMsg` extension function is unavailable.

- `ttl_unknown_policy::accept` (default) — responses without a TTL bypass the `receive_ttl_minimum` check and are processed normally.
- `ttl_unknown_policy::reject` — responses without a TTL are silently discarded, as if they had failed the TTL check.

## Why

No RFC rule requires a receive TTL check (RFC 6762 §11 has only the send-side SHOULD that responses carry IP TTL 255), so this policy, like the threshold, is hardening. Switch to `reject` when the TTL check is a deployment requirement and TTL extraction is known to work on the deployment platform. With `accept`, an attacker-controlled path that strips TTL information (or a custom socket that never supplies it) bypasses the TTL check entirely; `reject` closes that gap by treating "unknown" as "untrusted".

Keep `accept` when running over transports that structurally cannot supply a TTL — most notably custom policies and the inproc bus used in tests — or when interoperating on Windows hosts where extraction availability is uncertain.

## Danger

`reject` on a transport that never supplies the TTL discards **every** received response. A querying peer appears completely deaf — queries are sent but no response is ever processed — and no error is reported anywhere, because per-packet filtering is silent by design. This is the documented failure mode in [troubleshooting](../../troubleshooting.md#receive-ttl-on-transports-that-cannot-supply-it). Before enabling `reject`, verify that `recv_metadata::ttl` is populated on the target platform (see the platform matrix in [recv_metadata](../recv_metadata.md)).

`accept` (the default) is a deliberate availability-over-strictness trade-off: responses with a *known* below-threshold TTL are still rejected, but responses with no TTL information are trusted.

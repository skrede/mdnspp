# Encrypted mDNS Guide

## Overview

Encrypted mDNS is a project-specific extension that wraps standard mDNS
multicast traffic with XChaCha20-Poly1305 AEAD (Authenticated Encryption with
Associated Data). It is not defined by any RFC.

The extension provides:

- **Confidentiality**: the DNS payload is encrypted with XChaCha20-Poly1305
  using a 192-bit random nonce, making it safe for multi-sender scenarios
  without nonce coordination
- **Authentication**: the Poly1305 tag covers the full packet header and
  ciphertext, ensuring that forged or tampered packets are rejected
- **Anti-replay protection**: a sliding-window bitmap per sender session
  rejects duplicate or replayed sequence numbers for the sessions the receiver
  tracks; a packet of an untracked session is accepted once (see
  [Threat Model](threat-model.md))
- **Epoch-based key rotation**: a dual-key overlap during a grace period lets
  peers that rotate within that window keep communicating; rotation needs
  coordinated timing (see [Key Rotation](key-rotation.md))

Per-packet overhead is 68 bytes: a 52 byte header plus a 16 byte authentication
tag. The largest plaintext one packet can carry is `max_udp_payload - 68`, i.e.
8932 bytes.

## PSK Setup

A PSK is a 32-byte symmetric key represented by `mdnspp::encrypt::secure_key`. The
`secure_key` constructor copies a `std::array<std::byte, 32>` and zeroes its
own copy in the destructor. The caller's source array is the caller's
responsibility: wipe it with `secure_zero` once the `secure_key` has been
constructed.

```cpp
#include <array>
#include <cstddef>

// Fill from a secure source (e.g. read from file, environment variable, or RNG)
std::array<std::byte, 32> raw_key{};
// ... populate raw_key ...

mdnspp::encrypt::secure_key psk{raw_key};
mdnspp::encrypt::secure_zero(raw_key.data(), raw_key.size());
```

`secure_key` is move-only (copy-constructor and copy-assignment are deleted).

The PSK is placed in `encrypt_options` along with a non-zero `sender_id`.
The `sender_id` identifies this socket in the wire header; it must be distinct
for every socket on the multicast group (not merely per host or process) and
must not be zero. It is a label, not an authenticated identity: every holder
of the PSK can send under any `sender_id`:

```cpp
mdnspp::encrypt::encrypt_options enc_opts{
    .psk       = std::move(psk),
    .sender_id = 0x00000001,    // must be non-zero; distinct per socket
};
```

`encrypt_options` collects all encryption parameters:

| Field | Type | Default | Description |
|---|---|---|---|
| `psk` | `secure_key` | (empty) | Pre-shared symmetric key; an all-zero key is rejected at socket construction |
| `sender_id` | `uint32_t` | `0` | Non-zero sender identifier; validated at socket construction |
| `initial_epoch` | `uint32_t` | `0` | Epoch the socket starts at; provision after restarts so a peer rejoins a group that has rotated keys (see [Key Rotation](key-rotation.md)) |
| `accept_cleartext` | `bool` | `false` | Forward unencrypted packets to the application (unauthenticated downgrade path; see [Threat Model](threat-model.md)) |
| `auth_only` | `bool` | `false` | Send auth-only (plaintext + tag) packets instead of encrypted |
| `replay_window_size` | `uint16_t` | `64` | Anti-replay window width in sequence-number slots; 0 is rejected at socket construction |
| `max_senders` | `uint16_t` | `256` | Maximum tracked senders (LRU eviction when exceeded; 0 disables the limit) |
| `detection` | `cleartext_detection` | `magic_byte` | Strategy for identifying non-encrypted incoming packets |
| `recv_mode` | `receive_mode` | `accept_both` | Which packet types the receiver accepts |
| `max_sessions_per_sender` | `uint16_t` | `8` | Replay windows kept per sender, one per sender session (LRU eviction when exceeded); 0 is rejected at socket construction |

`encrypt_socket_options` extends `socket_options` (which carries interface
address, multicast TTL, and other socket parameters) with a nested
`encrypt_options encrypt` field:

```cpp
mdnspp::encrypt::encrypt_socket_options sock_opts{
    .encrypt = {
        .psk       = std::move(psk),
        .sender_id = 0x00000001,
    },
};
```

## Basic Usage

The convenience alias `mdnspp::encrypt::encrypted_observer` is defined in
`mdnspp/encrypt/defaults.h`:

```cpp
using encrypted_observer = basic_observer<encrypted_policy<default_policy>>;
```

It is constructed identically to `mdnspp::observer`, except it takes an
`encrypt_socket_options` argument:

```cpp
#include "mdnspp/encrypt/defaults.h"

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::encrypt::encrypt_socket_options opts{
        .encrypt = {
            .psk       = mdnspp::encrypt::secure_key{raw_key},
            .sender_id = 0x00000001,
        },
    };

    mdnspp::encrypt::encrypted_observer obs{
        ctx,
        mdnspp::observer_options{
            .on_record = [](const mdnspp::endpoint &sender,
                            const mdnspp::mdns_record_variant &rec)
            {
                std::visit([](const auto &r) { std::cout << r << std::endl; }, rec);
            }
        },
        std::move(opts)
    };

    obs.async_observe([&ctx](std::error_code) { ctx.stop(); });
    ctx.run();
}
```

The observer decrypts each received packet transparently before invoking the
`on_record` callback. The application sees plain `mdns_record_variant` values;
the encryption layer is invisible above the socket.

## Key Rotation

Key rotation replaces the active PSK with a new one. It is performed by
calling `update_key()` on the underlying `encrypted_socket`:

```cpp
socket.update_key(new_psk, mdnspp::encrypt::grace_period{
    .duration     = std::chrono::seconds{30},
    .packet_count = 1000,
});
```

`update_key()` may be called from any thread, concurrently with send and
receive. During the grace period the receiver accepts packets stamped with the
previous epoch (decrypted with the previous key). A peer that has not rotated
cannot read new-epoch traffic, so all peers must call `update_key()` within the
grace window; rotation is not seamless for a peer that rotates late. The
receiver also tries the current key for packets stamped one epoch ahead, which
only tolerates initial-epoch skew under the same key. A peer that restarts
after a rotation rejoins by setting `encrypt_options::initial_epoch` to the
group's current epoch.

See [Key Rotation](key-rotation.md) for epoch semantics, dual-key overlap,
the grace-period default bound, and peer coordination.

## Auth-Only Mode

Auth-only mode sends plaintext payloads with a Poly1305 authentication tag
instead of encrypting them. The receiver can authenticate the packet origin
without gaining confidentiality. Auth-only mode is enabled via
`encrypt_options::auth_only = true`.

See [Auth-Only Mode](auth-only-mode.md) for the wire format difference and
`receive_mode` control.

## Convenience Aliases

`mdnspp/encrypt/defaults.h` provides aliases for all eight mdnspp peer and
nic-group types parameterized on `encrypted_policy<default_policy>`:

| Alias | Underlying type |
|---|---|
| `encrypted_observer` | `basic_observer<encrypted_policy<default_policy>>` |
| `encrypted_querier` | `basic_querier<encrypted_policy<default_policy>>` |
| `encrypted_service_discovery` | `basic_service_discovery<encrypted_policy<default_policy>>` |
| `encrypted_service_server` | `basic_service_server<encrypted_policy<default_policy>>` |
| `encrypted_service_monitor` | `basic_service_monitor<encrypted_policy<default_policy>>` |
| `encrypted_nic_monitor` | `basic_nic_monitor<encrypted_policy<default_policy>>` |
| `encrypted_nic_group_options` | `basic_nic_group_options<encrypted_policy<default_policy>>` |
| `encrypted_dynamic_nic_group` | `basic_dynamic_nic_group<encrypted_policy<default_policy>>` |

The template alias `encrypted_nic_group<Peers...>` is also provided for
variadic multi-NIC group scenarios.

All aliases accept `encrypt_socket_options` where the plain aliases accept
`socket_options`. The remainder of the API is identical to the non-encrypted
variants.

## Wire Format

Each outgoing packet prepends a 52 byte header to the payload and appends a
16 byte Poly1305 authentication tag:

```
Offset  Size  Field
------  ----  -----
0       2     magic (0x4D43, big-endian)
2       1     version (0x02)
3       1     flags (0x01 = encrypted, 0x00 = auth-only)
4       4     sender_id (big-endian uint32_t)
8       8     session_id (big-endian uint64_t, random nonzero, drawn once per socket)
16      8     sequence (big-endian uint64_t, per-socket counter; the first packet carries 1)
24      4     epoch (big-endian uint32_t, incremented on each update_key())
28      24    nonce (random XChaCha20 nonce)
52      N     ciphertext (same length as plaintext for encrypted; plaintext for auth-only)
52+N    16    Poly1305 authentication tag
```

Total header size: 52 bytes (`encrypted_header_size`).
Total overhead: 68 bytes (`encrypted_overhead` = header + tag).

The 52 byte header is the AAD (Additional Authenticated Data) of the AEAD
operation; the AEAD authenticates the header and the ciphertext together under
the single Poly1305 tag. The header is therefore authenticated even though it
is transmitted unencrypted. (In auth-only mode the plaintext payload is also
covered as AAD; see [Auth-Only Mode](auth-only-mode.md).)

A receiver accepts only version 0x02. A packet of the earlier version 0x01
(44 byte header) is dropped in every configuration.

## Sending

`send(dest, plaintext, ec)` reports failures through `ec`; the throwing
`send(dest, plaintext)` calls it and throws `std::system_error` on error. A
plaintext larger than `max_udp_payload - 68` (8932 bytes) is not sent and
reports `encrypt_error::buffer_too_small`.

## Thread Safety

`send()` is as thread-safe as the inner socket's `send()`, but concurrent
`send()` calls on one socket are not supported: the socket reuses one send
buffer. `update_key()` may be called from any thread, concurrently with send
and receive. `async_receive()` and handler invocation follow the inner
socket's executor semantics.

## Allocation

In steady state the encrypt layer performs no heap allocation per datagram,
for either sending or receiving and delivering a packet. This is measured, not
assumed: a test counts global `operator new` calls across repeated send and
receive-deliver cycles and requires zero on a mock inner socket, on the default
socket (IPv4 loopback, Linux), and on the asio socket (IPv4 loopback, Linux),
where the count also equals that of a plain asio receive loop, which is zero as
well. On the asio path the mdnspp layers add no allocation; asio recycles its
own operation memory through a per-thread cache, and no allocation inside asio
itself was observed in steady state on Linux. The following are outside that
guarantee:

- The first datagram from a sender or session that the receiver does not yet
  track allocates replay-window state.
- IPv6, macOS and Windows were not measured.
- Code above the socket (peers, record parsing, caches) and the application's
  receive handler are not covered.

## Cleartext Handling

When encrypted mDNS is deployed alongside peers that have not yet migrated,
the `cleartext_detection` enum controls how non-encrypted incoming packets
are identified:

| Value | Behavior |
|---|---|
| `cleartext_detection::magic_byte` | Packets without the 0x4D43 magic prefix are treated as cleartext (default) |
| `cleartext_detection::attempt_decrypt` | As `magic_byte`, and additionally a magic-prefixed packet shorter than 44 bytes is treated as cleartext |
| `cleartext_detection::reject_all` | Packets without the magic prefix are silently dropped |

Setting `encrypt_options::accept_cleartext = true` passes cleartext packets
through to the application after the detection step. With `accept_cleartext =
false` (the default), cleartext packets are dropped regardless of
`cleartext_detection`.

A packet that starts with the magic prefix and is 44 bytes or longer is never
delivered as cleartext, whatever its version or header: it is authenticated if
it carries a version 0x02 header and dropped otherwise. An authentication
failure, a `receive_mode` mismatch, or a replay is a drop; none of them falls
through to cleartext. The receive path then re-arms and waits for the next
datagram.

Accepted cleartext is entirely unauthenticated: any sender on the LAN can
deliver packets to the application by omitting the magic prefix. See the
[Threat Model](threat-model.md) before enabling `accept_cleartext`.

In-band detection has an unavoidable collision: a cleartext DNS packet whose
16-bit transaction ID equals 0x4D43 starts with the magic prefix. In
`magic_byte` mode it is dropped at every size; in `attempt_decrypt` mode it is
delivered when shorter than 44 bytes and dropped when 44 bytes or longer, even
with `accept_cleartext` set. Multicast mDNS messages use transaction ID 0 and
are unaffected; legacy-unicast queries carry arbitrary IDs, so roughly one in
65536 such exchanges is lost.

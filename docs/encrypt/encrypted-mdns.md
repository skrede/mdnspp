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
- **Anti-replay protection**: a per-sender sliding-window bitmap rejects
  duplicate or replayed sequence numbers
- **Epoch-based key rotation**: peers can rotate PSKs with zero-downtime by
  using a dual-key overlap during a grace period

Per-packet overhead is 60 bytes: 44-byte header plus a 16-byte authentication
tag.

## PSK Setup

A PSK is a 32-byte symmetric key represented by `mdnspp::secure_key`. The
`secure_key` constructor takes a `std::array<std::byte, 32>` and zeroes the
array in its destructor, preventing key material from lingering in memory.

```cpp
#include <array>
#include <cstddef>

// Fill from a secure source (e.g. read from file, environment variable, or RNG)
std::array<std::byte, 32> raw_key{};
// ... populate raw_key ...

mdnspp::secure_key psk{raw_key};
```

`secure_key` is move-only (copy-constructor and copy-assignment are deleted).

The PSK is placed in `encrypt_options` along with a non-zero `sender_id`.
The `sender_id` identifies this peer in the wire header; it must be unique
across all senders on the multicast group and must not be zero:

```cpp
mdnspp::encrypt_options enc_opts{
    .psk       = std::move(psk),
    .sender_id = 0x00000001,    // must be non-zero; unique per sender
};
```

`encrypt_options` collects all encryption parameters:

| Field | Type | Default | Description |
|---|---|---|---|
| `psk` | `secure_key` | (empty) | Pre-shared symmetric key |
| `sender_id` | `uint32_t` | `0` | Non-zero sender identifier; validated on construction |
| `accept_cleartext` | `bool` | `false` | Forward unencrypted packets to the application |
| `auth_only` | `bool` | `false` | Send auth-only (plaintext + tag) packets instead of encrypted |
| `replay_window_size` | `uint16_t` | `64` | Anti-replay window width in sequence-number slots |
| `max_senders` | `uint16_t` | `256` | Maximum tracked senders (LRU eviction when exceeded) |
| `detection` | `cleartext_detection` | `magic_byte` | Strategy for identifying non-encrypted incoming packets |
| `recv_mode` | `receive_mode` | `accept_both` | Which packet types the receiver accepts |

`encrypt_socket_options` extends `socket_options` (which carries interface
address, multicast TTL, and other socket parameters) with a nested
`encrypt_options encrypt` field:

```cpp
mdnspp::encrypt_socket_options sock_opts{
    .encrypt = {
        .psk       = std::move(psk),
        .sender_id = 0x00000001,
    },
};
```

## Basic Usage

The convenience alias `mdnspp::encrypted_observer` is defined in
`mdnspp/encrypt/defaults.h`:

```cpp
using encrypted_observer = basic_observer<encrypted_policy<DefaultPolicy>>;
```

It is constructed identically to `mdnspp::observer`, except it takes an
`encrypt_socket_options` argument:

```cpp
#include "mdnspp/encrypt/defaults.h"

#include <iostream>

int main()
{
    mdnspp::context ctx;

    mdnspp::encrypt_socket_options opts{
        .encrypt = {
            .psk       = mdnspp::secure_key{raw_key},
            .sender_id = 0x00000001,
        },
    };

    mdnspp::encrypted_observer obs{
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

Key rotation replaces the active PSK with a new one without dropping packets
from peers that have not yet rotated. Rotation is performed by calling
`update_key()` on the underlying `encrypted_socket`:

```cpp
socket.update_key(new_psk, mdnspp::grace_period{
    .duration     = std::chrono::seconds{30},
    .packet_count = 1000,
});
```

See [Key Rotation](key-rotation.md) for epoch semantics, dual-key overlap,
and peer coordination.

## Auth-Only Mode

Auth-only mode sends plaintext payloads with a Poly1305 authentication tag
instead of encrypting them. The receiver can authenticate the packet origin
without gaining confidentiality. Auth-only mode is enabled via
`encrypt_options::auth_only = true`.

See [Auth-Only Mode](auth-only-mode.md) for the wire format difference and
`receive_mode` control.

## Convenience Aliases

`mdnspp/encrypt/defaults.h` provides aliases for all seven mdnspp peer types
parameterized on `encrypted_policy<DefaultPolicy>`:

| Alias | Underlying type |
|---|---|
| `encrypted_observer` | `basic_observer<encrypted_policy<DefaultPolicy>>` |
| `encrypted_querier` | `basic_querier<encrypted_policy<DefaultPolicy>>` |
| `encrypted_service_discovery` | `basic_service_discovery<encrypted_policy<DefaultPolicy>>` |
| `encrypted_service_server` | `basic_service_server<encrypted_policy<DefaultPolicy>>` |
| `encrypted_service_monitor` | `basic_service_monitor<encrypted_policy<DefaultPolicy>>` |
| `encrypted_nic_monitor` | `basic_nic_monitor<encrypted_policy<DefaultPolicy>>` |
| `encrypted_nic_group_options` | `basic_nic_group_options<encrypted_policy<DefaultPolicy>>` |
| `encrypted_dynamic_nic_group` | `dynamic_nic_group<encrypted_policy<DefaultPolicy>>` |

The template alias `encrypted_nic_group<Peers...>` is also provided for
variadic multi-NIC group scenarios.

All aliases accept `encrypt_socket_options` where the plain aliases accept
`socket_options`. The remainder of the API is identical to the non-encrypted
variants.

## Wire Format

Each outgoing packet prepends a 44-byte header to the encrypted payload and
appends a 16-byte Poly1305 authentication tag:

```
Offset  Size  Field
------  ----  -----
0       2     magic (0x4D43, big-endian)
2       1     version (0x01)
3       1     flags (0x01 = encrypted, 0x00 = auth-only)
4       4     sender_id (big-endian uint32_t)
8       8     sequence (big-endian uint64_t, per-sender monotonic counter)
16      4     epoch (big-endian uint32_t, incremented on each update_key())
20      24    nonce (random XChaCha20 nonce)
44      N     ciphertext (same length as plaintext for encrypted; plaintext for auth-only)
44+N    16    Poly1305 authentication tag
```

Total header size: 44 bytes (`encrypted_header_size`).
Total overhead: 60 bytes (`encrypted_overhead` = header + tag).

The header plus ciphertext (excluding the tag) are used as AAD
(Additional Authenticated Data) in the AEAD operation, so the full header
is authenticated even though it is not encrypted.

## Cleartext Handling

When encrypted mDNS is deployed alongside peers that have not yet migrated,
the `cleartext_detection` enum controls how non-encrypted incoming packets
are identified:

| Value | Behaviour |
|---|---|
| `cleartext_detection::magic_byte` | Packets without the 0x4D43 magic prefix are treated as cleartext (default) |
| `cleartext_detection::attempt_decrypt` | All packets are run through AEAD decryption; failures are treated as cleartext |
| `cleartext_detection::reject_all` | Packets without the magic prefix are silently dropped |

Setting `encrypt_options::accept_cleartext = true` passes cleartext packets
through to the application after the detection step. With `accept_cleartext =
false` (the default), cleartext packets are dropped regardless of
`cleartext_detection`.

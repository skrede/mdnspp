# Key Rotation

Key rotation replaces the active PSK on a live `encrypted_socket` without
dropping packets from peers that have not yet completed the rotation. The
mechanism is based on an epoch counter embedded in each packet header and a
configurable dual-key overlap period called the grace period.

## Epoch Semantics

The 32-bit `epoch` field in `encrypted_packet_header` starts at
`encrypt_options::initial_epoch` (default `0`) when the socket is constructed
and increments by 1 on each `update_key()` call. The sender stamps each
outgoing packet with the current epoch. The receiver uses the epoch to select
which key to attempt decryption with; the AEAD verification then decides
whether the packet is accepted.

The epoch is transmitted in the wire format at offset 16 in the 44-byte header
(big-endian `uint32_t`).

### initial_epoch

A peer that restarts after the group has rotated keys comes up with no memory
of past rotations. To rejoin, it must be provisioned with the group's current
key *and* the matching epoch:

```cpp
mdnspp::encrypt::encrypt_socket_options opts{
    .encrypt = {
        .psk           = mdnspp::encrypt::secure_key{current_group_key},
        .sender_id     = 0x00000007,
        .initial_epoch = 3,    // the group's current epoch
    },
};
```

Without `initial_epoch`, a restarted peer would stamp epoch 0 on its packets
and reject the group's current-epoch packets, leaving it silently unable to
communicate after any rotation.

## Dual-Key Overlap

Immediately after a call to `update_key()`, the socket holds two keys
simultaneously:

- **current key** (epoch N): used to encrypt all outgoing packets and to
  decrypt incoming packets with epoch = N or epoch = N+1
- **previous key** (epoch N-1): used only to decrypt incoming packets with
  epoch = N-1, as long as the grace period has not expired

The epoch N+1 case is attempted with the current key so that rotation does not
require all peers to act simultaneously: it accepts traffic from peers whose
epoch counter runs one ahead while holding the same key material (for example,
a peer provisioned with an `initial_epoch` one beyond ours while a rotation is
in flight). If the keys do not actually match, the AEAD verification fails and
the packet is dropped exactly like any forged packet.

Once the grace period expires, the previous key is zeroized (`sodium_memzero`)
and packets with epoch N-1 are rejected. Packets with any other epoch are
always rejected immediately, regardless of the grace period.

Note the inherent asymmetry during a staggered rotation: a peer that has not
yet rotated does not hold the new key and therefore cannot decrypt new-epoch
traffic until its own `update_key()` call; rotated peers, however, keep
accepting its old-epoch traffic for the duration of their grace window.

## Grace Period

The `grace_period` struct controls how long the previous key is accepted:

```cpp
struct grace_period
{
    std::optional<std::chrono::nanoseconds> duration;
    std::optional<uint64_t>                 packet_count;
};
```

If neither `duration` nor `packet_count` is set, `update_key()` applies a
default duration bound of 30 seconds
(`encrypted_socket::default_grace_duration`), so the previous key can never
remain accepted indefinitely. When both are set, the grace period expires when
either condition is first satisfied.

| Field | Type | Description |
|---|---|---|
| `duration` | `std::optional<std::chrono::nanoseconds>` | Expire after this wall-clock duration |
| `packet_count` | `std::optional<uint64_t>` | Expire after this many old-epoch packets are received |

## Lazy Expiry

The grace period is checked inline on each received packet. There is no
background timer. The check compares the elapsed time since `update_key()` was
called (measured with `std::chrono::steady_clock`) and the count of old-epoch
packets seen since rotation. This means that grace expiry is bounded by the
arrival of the next packet, not by wall-clock accuracy. As soon as expiry is
observed, the previous key is zeroized rather than retained until destruction.

## update_key()

```cpp
void update_key(secure_key new_psk, grace_period gp);
```

Called on the `encrypted_socket` (accessible via `peer.socket()` for
policy-wrapped types). Thread-safe: `update_key()` may be called from any
thread, concurrently with the receive path; the socket's key, epoch, and
grace-period state are guarded by an internal mutex. Effects:

1. The current key becomes the previous key
2. The new key is copied from `new_psk`
3. The epoch is incremented
4. Grace period state is initialised with the provided `gp` parameters
   (with the 30-second default duration if `gp` is empty)

`secure_key` is move-only; the caller transfers ownership of the key material.
`secure_key` copies the source array, so the caller must wipe its own source
buffer after construction:

```cpp
std::array<std::byte, 32> new_raw_key{};
// ... populate new_raw_key from a secure source ...

socket.update_key(
    mdnspp::encrypt::secure_key{new_raw_key},
    mdnspp::encrypt::grace_period{.duration = std::chrono::seconds{30}}
);
mdnspp::encrypt::secure_zero(new_raw_key.data(), new_raw_key.size());
```

## Rotation Example

The following sketch shows a staggered rotation across two peers. Both peers
must call `update_key()` with the same new key and a grace period long enough
for all in-flight packets from the old epoch to be delivered.

```cpp
// Peer A rotates first: epoch N -> N+1.
socket_a.update_key(
    mdnspp::encrypt::secure_key{new_raw_key},
    mdnspp::encrypt::grace_period{.duration = std::chrono::seconds{30}}
);

// Until Peer B rotates:
//   - B -> A traffic (epoch N, old key) is still accepted by A via A's
//     previous key during A's grace window.
//   - A -> B traffic (epoch N+1, new key) is NOT decryptable by B: B does
//     not hold the new key yet. This direction is interrupted until B
//     rotates, which is why the rotation window should be short.
socket_b.update_key(
    mdnspp::encrypt::secure_key{new_raw_key},
    mdnspp::encrypt::grace_period{.duration = std::chrono::seconds{30}}
);
// Both peers are now at epoch N+1 and communicate bidirectionally.
```

A practical coordination strategy: broadcast a rotation signal (for example, a
service announcement attribute) that instructs all peers to load a new key and
call `update_key()` within a nominated window.

## Acceptance Rules

| Packet epoch | Grace period | Key tried | Result |
|---|---|---|---|
| N (current) | any | current | Accepted if AEAD verification passes |
| N+1 | any | current | Accepted if AEAD verification passes (epoch-counter skew with shared key) |
| N-1 (previous) | not expired | previous | Accepted if AEAD verification passes |
| N-1 (previous) | expired | none | Rejected (previous key already zeroized) |
| any other | any | none | Rejected |

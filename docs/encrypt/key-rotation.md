# Key Rotation

Key rotation replaces the active PSK on a live `encrypted_socket` without
dropping packets from peers that have not yet completed the rotation. The
mechanism is based on an epoch counter embedded in each packet header and a
configurable dual-key overlap period called the grace period.

## Epoch Semantics

The 32-bit `epoch` field in `encrypted_packet_header` starts at `0` when the
socket is constructed and increments by 1 on each `update_key()` call. The
sender stamps each outgoing packet with the current epoch. The receiver uses the
epoch to select which key to attempt decryption with.

The epoch is transmitted in the wire format at offset 16 in the 44-byte header
(big-endian `uint32_t`).

## Dual-Key Overlap

Immediately after a call to `update_key()`, the socket holds two keys
simultaneously:

- **current key** (epoch N): used to encrypt all outgoing packets and to decrypt
  incoming packets with epoch = N
- **previous key** (epoch N-1): used only to decrypt incoming packets with
  epoch = N-1, as long as the grace period has not expired

Once the grace period expires, packets with epoch N-1 are rejected. Packets
with epoch < N-1 are always rejected immediately, regardless of the grace period.

## Grace Period

The `grace_period` struct controls how long the previous key is accepted:

```cpp
struct grace_period
{
    std::optional<std::chrono::nanoseconds> duration;
    std::optional<uint64_t>                 packet_count;
};
```

At least one of `duration` or `packet_count` must be set; `update_key()` asserts
this precondition. When both are set, the grace period expires when either
condition is first satisfied.

| Field | Type | Description |
|---|---|---|
| `duration` | `std::optional<std::chrono::nanoseconds>` | Expire after this wall-clock duration |
| `packet_count` | `std::optional<uint64_t>` | Expire after this many old-epoch packets are received |

## Lazy Expiry

The grace period is checked inline on each received packet that uses the
previous epoch key. There is no background timer. The check compares the
elapsed time since `update_key()` was called (measured with
`std::chrono::steady_clock`) and the count of old-epoch packets seen since
rotation. This means that grace expiry is bounded by the arrival of the next
packet, not by wall-clock accuracy.

## update_key()

```cpp
void update_key(secure_key new_psk, grace_period gp);
```

Called on the `encrypted_socket` (accessible via `socket.inner()` for
policy-wrapped types). Effects:

1. Previous key is saved as the backup key
2. New key is copied from `new_psk`
3. Epoch is incremented
4. Grace period state is initialised with the provided `gp` parameters

`secure_key` is move-only; the caller transfers ownership of the key material:

```cpp
std::array<std::byte, 32> new_raw_key{};
// ... populate new_raw_key from a secure source ...

socket.update_key(
    mdnspp::encrypt::secure_key{new_raw_key},
    mdnspp::encrypt::grace_period{.duration = std::chrono::seconds{30}}
);
```

## Rotation Example

The following sketch shows a coordinated rotation across two peers. Both peers
must call `update_key()` with the same new key and a grace period long enough
for all in-flight packets from the old epoch to be delivered.

```cpp
// Peer A (sender): rotate to new_key, allow 30 s for Peer B to catch up
socket_a.update_key(
    mdnspp::encrypt::secure_key{new_raw_key},
    mdnspp::encrypt::grace_period{.duration = std::chrono::seconds{30}}
);

// Peer B (receiver): must also rotate to new_key within the grace window.
// Until Peer B rotates, it decrypts Peer A's packets with the previous key.
// After Peer B rotates, it uses the new key for both sends and receives.
socket_b.update_key(
    mdnspp::encrypt::secure_key{new_raw_key},
    mdnspp::encrypt::grace_period{.duration = std::chrono::seconds{30}}
);
```

A practical coordination strategy: broadcast a rotation signal (for example, a
service announcement attribute) that instructs all peers to load a new key and
call `update_key()` within a nominated window.

## Rejection Rules

| Packet epoch | Grace period | Result |
|---|---|---|
| N (current) | any | Accepted (decrypts with current key) |
| N-1 (previous) | not expired | Accepted (decrypts with previous key) |
| N-1 (previous) | expired | Rejected |
| < N-1 | any | Rejected |

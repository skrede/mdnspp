# encrypt_options

Encryption configuration for an `encrypted_socket`. Groups the pre-shared key, sender identity, replay window parameters, cleartext handling policy, and operating mode.

## Header

```cpp
#include <mdnspp/encrypt/encrypt_options.h>
```

## Types in This Header

This header defines four related types: `encrypt_options`, `cleartext_detection`, `receive_mode`, and `grace_period`.

---

## encrypt_options

```cpp
struct encrypt_options
{
    secure_key          psk;
    uint32_t            sender_id{0};
    uint32_t            initial_epoch{0};
    bool                accept_cleartext{false};
    bool                auth_only{false};
    uint16_t            replay_window_size{64};
    uint16_t            max_senders{256};
    cleartext_detection detection{cleartext_detection::magic_byte};
    receive_mode        recv_mode{receive_mode::accept_both};
    uint16_t            max_sessions_per_sender{8};

    std::error_code validate() const noexcept;
};
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `psk` | `secure_key` | zero-filled | Pre-shared key (32 bytes). The key is copied into the socket on construction; an all-zero key fails `validate()`. |
| `sender_id` | `uint32_t` | `0` | Non-zero identifier embedded in every sent packet. Every socket on the encrypted multicast group must use a distinct non-zero value (distinct per socket, not merely per host or process); `0` fails `validate()`. The value is a label, not an authenticated identity: any holder of the PSK can send under any `sender_id`. |
| `initial_epoch` | `uint32_t` | `0` | Epoch the socket starts at. A peer that restarts after the group has rotated keys must be provisioned with the current group key and the matching epoch to rejoin (see [Key Rotation](../key-rotation.md)). |
| `accept_cleartext` | `bool` | `false` | When `true`, packets classified as cleartext by `detection` (see `cleartext_detection` for the exact rule) are forwarded to the receive handler instead of being silently dropped. Accepted cleartext is entirely unauthenticated -- see the [Threat Model](../threat-model.md). A legitimate cleartext packet of 44 bytes or more whose DNS transaction ID is `0x4D43` starts with the magic bytes and is dropped even with `accept_cleartext` set; shorter packets with that ID are delivered only with `cleartext_detection::attempt_decrypt`. |
| `auth_only` | `bool` | `false` | When `true`, outgoing packets carry the plaintext payload in the clear, covered together with the header by the AEAD tag -- no encryption is applied (the `flag_encrypted` bit is cleared). Integrity is still verified by the AEAD tag. |
| `replay_window_size` | `uint16_t` | `64` | Number of sequence numbers tracked per sender session in the replay protection window. The full `uint16_t` range is supported (the bitmap is sized to the window, 8 bytes per 64 slots per session); `0` fails `validate()`. |
| `max_senders` | `uint16_t` | `256` | Maximum number of distinct `sender_id` values tracked in the replay window. When a new sender is seen beyond this limit, the least recently used sender is evicted with all its sessions. `0` fails `validate()`. |
| `detection` | `cleartext_detection` | `magic_byte` | Strategy used to distinguish encrypted packets from cleartext on receive. See `cleartext_detection`. |
| `recv_mode` | `receive_mode` | `accept_both` | Filters accepted packets by encryption mode. See `receive_mode`. |
| `max_sessions_per_sender` | `uint16_t` | `8` | Independent replay windows kept per sender, one per sender session (a sender opens a new session each time a socket is constructed, e.g. on restart). When a sender exceeds this, its least recently used session is evicted. `0` fails `validate()`. See [Replay window memory](#replay-window-memory). |

### Replay window memory

A tracked sender costs at most

```
max_sessions_per_sender * ceil(replay_window_size / 64) * 8   bytes
```

of bitmap, plus container bookkeeping: 64 bytes at the defaults (64 slots, 8 sessions). Worst case with the default `max_sessions_per_sender` and the maximum `replay_window_size` of 65535 is 64 KiB per sender, and about 16 MiB across the default `max_senders` of 256. Windows are created as sessions appear, so the worst case is reached only when every tracked sender has opened that many sessions.

A packet of a session that is not tracked (never seen, evicted by the session or sender limit, or recorded before the receiver restarted) is accepted once; see the [Threat Model](../threat-model.md). Raising the limits increases memory and the number of recordings an attacker needs, but does not remove that residual.

### Methods

#### validate

```cpp
std::error_code validate() const noexcept;
```

Returns `std::errc::invalid_argument` if `sender_id` is zero, the PSK is all-zero, `replay_window_size` is zero, `max_senders` is zero, or `max_sessions_per_sender` is zero; a default-constructed (falsy) `std::error_code` otherwise. Enforced in all build configurations by the `encrypted_socket` constructors that accept `encrypt_socket_options`: the throwing constructor throws `std::system_error`, the `std::error_code` constructor sets `ec`; in both cases validation runs before the key is copied.

---

## cleartext_detection

```cpp
enum class cleartext_detection { magic_byte, attempt_decrypt, reject_all };
```

Controls how `encrypted_socket` classifies a received datagram before authentication. Cleartext is forwarded only when `accept_cleartext` is `true`; otherwise it is dropped.

| Enumerator | Value | Behavior |
|------------|-------|----------|
| `magic_byte` | `0` | A packet not starting with the two-byte magic `0x4D 0x43` is cleartext, whatever its size. |
| `attempt_decrypt` | `1` | As `magic_byte`; in addition, a magic-prefixed packet shorter than 44 bytes (`smallest_known_header_size`) is cleartext. |
| `reject_all` | `2` | Packets not starting with the magic are dropped regardless of `accept_cleartext`. Magic-prefixed packets are handled as in the other modes. |

Rules common to all three modes for a packet that starts with the magic:

- Shorter than 44 bytes: dropped, except cleartext in `attempt_decrypt` with `accept_cleartext`.
- 44 bytes or longer: never delivered as cleartext, whatever its version byte or header contents. It is authenticated if it is at least `encrypted_overhead` (68) bytes long and carries version `0x02`, and dropped otherwise. Consequently a version `0x01` packet is rejected in every configuration.
- A packet that fails authentication, does not match `recv_mode`, or is a replay is dropped. None of these falls through to cleartext, and local errors such as `buffer_too_small` never do.

Residual: a legitimate cleartext packet of 44 bytes or more whose DNS transaction ID is `0x4D43` starts with the magic and is therefore dropped under `accept_cleartext` in every mode; shorter ones are delivered only with `attempt_decrypt`.

---

## receive_mode

```cpp
enum class receive_mode { accept_both, encrypted_only, auth_only };
```

Filters received packets by their encryption mode bit. The check runs after the packet has authenticated, so a packet that does not match is dropped; it is never delivered as cleartext.

| Enumerator | Value | Behavior |
|------------|-------|----------|
| `accept_both` | `0` | Accepts both encrypted packets (`flag_encrypted` set) and auth-only packets (`flag_encrypted` cleared). |
| `encrypted_only` | `1` | Accepts only packets with `flag_encrypted` set. Auth-only packets are silently dropped. |
| `auth_only` | `2` | Accepts only packets with `flag_encrypted` cleared (auth-only mode). Encrypted packets are silently dropped. |

---

## grace_period

```cpp
struct grace_period
{
    std::optional<std::chrono::nanoseconds> duration;
    std::optional<uint64_t>                 packet_count;
};
```

Defines the overlap window during key rotation. After `update_key()` is called, the previous key remains accepted for decrypting packets from peers that have not yet switched, until the grace period expires; peers must rotate within that window (see [Key Rotation](../key-rotation.md)). The grace period expires when either condition is met.

If neither field is set, `update_key()` applies a duration bound of `encrypted_socket::default_grace_duration` (`std::chrono::seconds{30}`) so the previous key cannot remain accepted indefinitely. Expiry is checked at every key lookup, on the send path and the receive path, and the previous key is zeroized as soon as it is observed (see [Lazy Expiry](../key-rotation.md#lazy-expiry)).

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `duration` | `std::optional<std::chrono::nanoseconds>` | Time since `update_key()`, measured with `std::chrono::steady_clock`, for which the previous key is accepted. `std::nullopt` disables time-based expiry. |
| `packet_count` | `std::optional<uint64_t>` | Number of packets accepted with the previous key (authenticated and not rejected as replays) before it is invalidated. `std::nullopt` disables count-based expiry. |

## See Also

- [encrypted_socket](encrypted_socket.md) -- transparent encrypt/decrypt socket wrapper
- [encrypt_socket_options](encrypt_socket_options.md) -- combines `socket_options` with `encrypt_options`
- [secure_key](secure_key.md) -- RAII key container with zeroing destructor
- [Key Rotation](../key-rotation.md) -- epoch-based dual-key overlap semantics

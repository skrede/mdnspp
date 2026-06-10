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

    [[nodiscard]] std::error_code validate() const noexcept;
};
```

### Fields

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `psk` | `secure_key` | zero-filled | Pre-shared key (32 bytes). The key is copied into the socket on construction; an all-zero key fails `validate()`. |
| `sender_id` | `uint32_t` | `0` | Non-zero identifier embedded in every sent packet. Each participant on the encrypted multicast group must use a distinct non-zero value; `0` fails `validate()`. |
| `initial_epoch` | `uint32_t` | `0` | Epoch the socket starts at. A peer that restarts after the group has rotated keys must be provisioned with the current group key and the matching epoch to rejoin (see [Key Rotation](../key-rotation.md)). |
| `accept_cleartext` | `bool` | `false` | When `true`, cleartext (non-encrypted) packets that cannot be decrypted are forwarded to the receive handler instead of being silently dropped. Accepted cleartext is entirely unauthenticated -- see the [Threat Model](../threat-model.md). |
| `auth_only` | `bool` | `false` | When `true`, outgoing packets carry the plaintext payload as additional authenticated data only -- no encryption is applied (the `flag_encrypted` bit is cleared). Integrity is still verified by the AEAD tag. |
| `replay_window_size` | `uint16_t` | `64` | Number of sequence numbers tracked per sender in the replay protection window. The full `uint16_t` range is supported (the bitmap is sized to the window, 8 bytes per 64 slots per sender); `0` fails `validate()`. |
| `max_senders` | `uint16_t` | `256` | Maximum number of distinct `sender_id` values tracked in the replay window. Senders beyond this limit are evicted. |
| `detection` | `cleartext_detection` | `magic_byte` | Strategy used to distinguish encrypted packets from cleartext on receive. See `cleartext_detection`. |
| `recv_mode` | `receive_mode` | `accept_both` | Filters accepted packets by encryption mode. See `receive_mode`. |

### Methods

#### validate

```cpp
[[nodiscard]] std::error_code validate() const noexcept;
```

Returns `std::errc::invalid_argument` if `sender_id` is zero, the PSK is all-zero, or `replay_window_size` is zero; a default-constructed (falsy) `std::error_code` otherwise. Enforced in all build configurations by the `encrypted_socket` constructors that accept `encrypt_socket_options`: the throwing constructor throws `std::system_error`, the `std::error_code` constructor sets `ec`; in both cases validation runs before the key is copied.

---

## cleartext_detection

```cpp
enum class cleartext_detection { magic_byte, attempt_decrypt, reject_all };
```

Controls how `encrypted_socket` identifies encrypted packets on receive.

| Enumerator | Value | Behavior |
|------------|-------|----------|
| `magic_byte` | `0` | Packets starting with the two-byte magic sequence `0x4D 0x43` are treated as encrypted. Other packets are either forwarded as cleartext (if `accept_cleartext` is `true`) or silently dropped. |
| `attempt_decrypt` | `1` | All packets are passed through the AEAD decryptor. If decryption fails and `accept_cleartext` is `true`, the raw packet is forwarded as cleartext. |
| `reject_all` | `2` | Packets not starting with the magic sequence are silently rejected, regardless of `accept_cleartext`. |

---

## receive_mode

```cpp
enum class receive_mode { accept_both, encrypted_only, auth_only };
```

Filters received packets by their encryption mode bit after the magic-byte check.

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

Defines the overlap window during key rotation. After `update_key()` is called, the previous key remains accepted for decrypting packets from peers that have not yet switched. The grace period expires when either condition is met.

If neither field is set, `update_key()` applies a duration bound of `encrypted_socket::default_grace_duration` (`std::chrono::seconds{30}`) so the previous key cannot remain accepted indefinitely. On expiry the previous key is zeroized.

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `duration` | `std::optional<std::chrono::nanoseconds>` | Wall-clock time for which the previous key is accepted. `std::nullopt` disables time-based expiry. |
| `packet_count` | `std::optional<uint64_t>` | Number of packets successfully decrypted with the previous key before it is invalidated. `std::nullopt` disables count-based expiry. |

## See Also

- [encrypted_socket](encrypted_socket.md) -- transparent encrypt/decrypt socket wrapper
- [encrypt_socket_options](encrypt_socket_options.md) -- combines `socket_options` with `encrypt_options`
- [secure_key](secure_key.md) -- RAII key container with zeroing destructor
- [Key Rotation](../key-rotation.md) -- epoch-based dual-key overlap semantics

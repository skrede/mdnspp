# encrypted_socket

Transparent encrypt/decrypt wrapper around any `SocketLike` socket. Satisfies the `SocketLike` concept itself, so it can be composed directly into `encrypted_policy`. Outgoing packets are encrypted with XChaCha20-Poly1305 AEAD; incoming packets are decrypted and anti-replay-checked before being delivered to the receive handler.

## Header and Alias

| Form | Header |
|------|--------|
| `encrypted_socket<InnerSocket>` | `#include <mdnspp/encrypt/encrypted_socket.h>` |

```cpp
template <SocketLike InnerSocket>
class encrypted_socket;
```

## Template Parameters

| Parameter | Constraint | Description |
|-----------|------------|-------------|
| `InnerSocket` | satisfies `SocketLike` | The underlying socket used for actual network I/O. Typically the `socket_type` of a concrete policy such as `DefaultSocket` or `AsioSocket`. |

## Constructors

All four constructors accept a forwarding reference `Executor&&` to avoid copy-construction of the inner socket on compilers where by-value template parameters trigger premature instantiation (Apple Clang 16 bug). The requires-clause excludes `encrypted_socket` itself to prevent the forwarding constructor from shadowing move construction.

### Throwing, executor only

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex);
```

Constructs the inner socket from `ex`. Encryption options are left at their defaults (zero key, `sender_id = 0`, `magic_byte` detection). The sender_id must be set before any packet is sent.

### Non-throwing, executor only

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, std::error_code &ec);
```

Same as above, but sets `ec` instead of throwing if the inner socket fails to construct.

### Throwing, with options

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts);
```

Constructs the inner socket from `ex` and the base `socket_options` portion of `opts`. Copies the PSK, configures replay window, cleartext and auth-only flags, and calls `opts.encrypt.validate()`. This is the primary constructor for production use.

### Non-throwing, with options

```cpp
template <typename Executor>
    requires (!std::is_same_v<std::remove_cvref_t<Executor>, encrypted_socket>)
explicit encrypted_socket(Executor &&ex, const encrypt_socket_options &opts, std::error_code &ec);
```

Same as the throwing with-options constructor, but sets `ec` instead of throwing on inner socket construction failure.

## Copy and Move

`encrypted_socket` is non-copyable. It is move-constructible (defaulted) but move-assignment is deleted to prevent accidental key leakage across live sockets.

```cpp
encrypted_socket(const encrypted_socket &) = delete;
encrypted_socket &operator=(const encrypted_socket &) = delete;

encrypted_socket(encrypted_socket &&other) noexcept = default;
encrypted_socket &operator=(encrypted_socket &&) = delete;
```

## Destructor

```cpp
~encrypted_socket();
```

Zeroes both the current key and the previous key (held during grace periods) using `secure_zero` before the object is destroyed.

## Methods

### close

```cpp
void close();
```

Closes the underlying inner socket. Ongoing `async_receive` operations complete with an error.

### send (throwing)

```cpp
void send(const endpoint &dest, std::span<const std::byte> plaintext);
```

Encrypts `plaintext` with the current epoch key and `sender_id`, then passes the resulting ciphertext to the inner socket's `send`. The sequence counter is incremented atomically.

When `auth_only` mode is enabled, the plaintext is included as additional authenticated data and no ciphertext is produced; the packet carries only the AEAD tag and header.

### send (non-throwing)

```cpp
void send(const endpoint &dest, std::span<const std::byte> plaintext, std::error_code &ec);
```

Same as the throwing overload, but sets `ec` instead of throwing if the underlying send fails.

### async_receive

```cpp
void async_receive(
    detail::move_only_function<void(const recv_metadata &, std::span<std::byte>)> handler);
```

Arms the inner socket's receive loop. For each received datagram, the socket:

1. Checks for the encrypted magic byte sequence (`0x4D 0x43`) according to `cleartext_detection`.
2. Deserializes the packet header to extract `sender_id`, `sequence`, `epoch`, and `flags`.
3. Filters by `receive_mode` (encrypted-only or auth-only-only).
4. Selects the current key (matching epoch) or the previous key (epoch minus one, within grace period).
5. Decrypts with AEAD. On failure, optionally forwards as cleartext if `accept_cleartext` is set.
6. Checks the per-sender replay window. Duplicate or replayed sequences are silently dropped.
7. Calls `handler` with the decrypted plaintext.

### update_key

```cpp
void update_key(secure_key new_psk, grace_period gp);
```

Performs a key rotation. The current key becomes the previous key and is retained for decrypting packets from peers still using the old epoch. The new key is installed as the current key, the epoch counter is incremented by one, and the grace period timer is started.

`gp` must have at least one of `duration` or `packet_count` set. The previous key is evicted when the grace period expires -- either when the wall-clock duration elapses or when the packet count of old-epoch packets received exceeds the limit, whichever comes first.

### inner

```cpp
InnerSocket &inner() noexcept;
const InnerSocket &inner() const noexcept;
```

Returns a reference to the wrapped inner socket. Provides access to socket-specific operations not exposed through `SocketLike` (e.g., `native_handle()` on platform socket types).

## Key State

| State | Description |
|-------|-------------|
| Current key | Used for all outgoing packets. Used for decrypting packets with the current epoch number. |
| Previous key | Retained after `update_key()`. Accepted for decrypting packets with epoch minus one, until the grace period expires. Zeroed on grace period expiry and on destruction. |
| Epoch | Monotonically increasing `uint32_t`. Incremented on each `update_key()` call. Embedded in every outgoing packet header. |

## Usage Example

```cpp
#include <mdnspp/encrypt/defaults.h>
#include <mdnspp/encrypt/encrypt_options.h>
#include <mdnspp/encrypt/encrypt_socket_options.h>

#include <array>

// Construct an encrypted observer using a pre-shared key
std::array<std::byte, 32> raw_key{};
// ... fill raw_key ...

mdnspp::encrypt_socket_options sock_opts;
sock_opts.encrypt.psk       = mdnspp::secure_key{raw_key};
sock_opts.encrypt.sender_id = 1;

mdnspp::context ctx;
mdnspp::encrypted_observer obs{ctx, mdnspp::observer_options{}, std::move(sock_opts)};
obs.async_observe();
ctx.run();
```

## See Also

- [encrypt_options](encrypt_options.md) -- encryption configuration
- [encrypt_socket_options](encrypt_socket_options.md) -- combines socket and encryption options
- [encrypted_policy](encrypted_policy.md) -- policy wrapper that substitutes `encrypted_socket` for the inner socket type
- [secure_key](secure_key.md) -- RAII key container
- [Key Rotation](../key-rotation.md) -- grace period semantics and `update_key()` usage
